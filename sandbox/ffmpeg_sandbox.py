"""ffmpeg'i izole bir ad alanında çalıştıran sarmalayıcı.

Tehdit modeli: yüklenen video **düşman girdisidir**. libavcodec/libavformat
geniş bir ayrıştırıcı yüzeyi ve uzun bir bellek bozulması geçmişi taşıyor.
Varsayım şu: bir gün ffmpeg süreci içinde saldırganın kodu çalışacak.
Buradaki katmanların hiçbiri bunu *önlemiyor*; hepsi o kodun ne
yapabileceğini daraltıyor.

Katmanlar (her biri tek başına da bir şey ifade ediyor):

1. **Ayrı süreç.** ffmpeg asla Flask işçisinin içinde, kütüphane bağlaması
   olarak çalışmıyor. Aynı adres alanında olsaydı bir yığın taşması
   ``.secret_key``, oturum anahtarı ve ``videos.json``'ı doğrudan ele
   geçirirdi.
2. **Protokol kısıtı.** ``-protocol_whitelist file`` ve açık demuxer.
   ffmpeg'in playlist/concat üzerinden yerel dosya okuma ve SSRF sınıfı
   sorunları bellek hatası bile gerektirmiyor; bu katman onları kapatıyor.
3. **Ad alanları.** user + mount + pid + net + ipc + uts. Ağ ad alanı boş:
   tam RCE durumunda bile dışarı veri sızdıracak bir soket yok.
4. **Minimal kök dosya sistemi.** tmpfs kök; yalnızca ffmpeg ikilisi
   (salt okunur), girdi dosyası (salt okunur) ve çıktı dizini (yazılır)
   görünüyor. Kabuk yok, /etc yok, /proc yok.
5. **Seccomp izin listesi.** Ölçülmüş syscall kümesi; ağ, süreç çatallama,
   ptrace, mount, bpf ve benzeri sınıflar yok (bkz. seccomp.py).
6. **Kaynak sınırları.** Bellek, CPU, çıktı boyutu, dosya tanıtıcısı ve
   duvar saati. Bellek bombalarını ve sonsuz kodlamayı kesiyor.
7. **Çıktı doğrulaması.** Çıktı boş ve yeni bir dizine yazılıyor; tek
   dosya, boyut sınırı ve atomik yerine koyma.

Kapatamadığımız şey dürüstçe: ``execve`` izin listesinde kalmak zorunda
(filtreyi exec'ten önce kuruyoruz). Bunu seccomp değil AppArmor kapatıyor -
bkz. ``sandbox/apparmor/``. Ayrıca çekirdeğin kendisi hâlâ saldırı yüzeyi.

Fail-closed: izolasyon katmanları kurulamıyorsa ffmpeg **hiç
çalıştırılmıyor**. Korumasız çalıştırmak en kötü sonuç olurdu.
"""

import argparse
import ctypes
import ctypes.util
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

from . import seccomp

# --- mount(2) bayrakları ---------------------------------------------------
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2
_SYS_PIVOT_ROOT = 155  # x86_64

# Sandbox içindeki sabit yollar. Girdinin adı da sabitleniyor: özgün ad
# saldırgan kontrolünde ve ffmpeg bazı seçenekleri dosya adından türetiyor.
_IN_PATH = "/in/input"
_OUT_DIR = "/out"
_FFMPEG_PATH = "/ffmpeg"

# Uzantıdan demuxer'a eşleme. Açık demuxer vermek içerik tipini sabitliyor:
# .mp4 diye yüklenmiş bir Matroska, tahmin edilip açılmak yerine reddediliyor.
DEMUXER_BY_EXTENSION = {
    ".mp4": "mp4", ".m4v": "mp4", ".mov": "mov",
    ".webm": "matroska,webm", ".ogg": "ogg", ".ogv": "ogg",
}

# Kodlama profilleri. Çağıranın serbest ffmpeg argümanı vermesine bilerek
# izin verilmiyor: serbest argüman başlı başına bir enjeksiyon yüzeyi
# ("-i http://...", "-f lavfi -i ...") ve izolasyonun üstünden atlar.
PROFILES = {
    "web-720p": [
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
        "-vf", "scale='min(1280,iw)':-2",
        "-c:a", "aac", "-b:a", "128k",
        "-movflags", "+faststart",
    ],
    "thumbnail": [
        "-frames:v", "1", "-vf", "scale=320:-2", "-f", "image2",
    ],
}

# Profilin ürettiği kodekler kapsayıcıyla uyumlu olmalı. Çıktı uzantısı
# kapsayıcıyı belirlediği için eşleşmeyi burada denetliyoruz; yoksa hata
# ffmpeg'in içinden anlaşılması zor bir mux hatası olarak geliyor.
PROFILE_EXTENSIONS = {
    "web-720p": {".mp4", ".m4v"},
    "thumbnail": {".jpg", ".jpeg", ".png"},
}


class SandboxError(Exception):
    """Sandbox kurulamadı ya da kurallara uyulmadı."""


class TranscodeError(Exception):
    """ffmpeg çalıştı ama iş başarısız oldu."""

    def __init__(self, message, returncode=None, stderr=""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class Policy:
    """Sandbox ayarları. Varsayılanlar 720p yeniden kodlama için ölçüldü.

    ``memory_bytes`` RLIMIT_AS'e gidiyor, yani *sanal adres alanını*
    sınırlıyor - gerçek kullanımı değil. x264 cömert rezervasyon yaptığı için
    ikisi arasındaki fark büyük: 1 GiB'de pthread_create EAGAIN veriyor,
    2 GiB'de aynı iş 0.1 saniyede bitiyor. Değer ölçülerek seçildi.
    Gerçek bellek tavanı isteniyorsa doğru araç cgroup ``memory.max``;
    o da devredilmiş bir cgroup ağacı gerektiriyor.
    """

    def __init__(
        self,
        ffmpeg_path=None,
        memory_bytes=2 * 1024 * 1024 * 1024,
        cpu_seconds=120,
        wall_clock_seconds=180,
        max_output_bytes=512 * 1024 * 1024,
        max_open_files=64,
        max_alloc_bytes=256 * 1024 * 1024,
        tmpfs_bytes=64 * 1024 * 1024,
        threads=2,
        stderr_limit=8192,
        apparmor_profile=None,
        syscalls=None,
    ):
        self.ffmpeg_path = ffmpeg_path or os.environ.get("FFMPEG_PATH", "/usr/bin/ffmpeg")
        self.memory_bytes = memory_bytes
        self.cpu_seconds = cpu_seconds
        self.wall_clock_seconds = wall_clock_seconds
        self.max_output_bytes = max_output_bytes
        self.max_open_files = max_open_files
        self.max_alloc_bytes = max_alloc_bytes
        self.tmpfs_bytes = tmpfs_bytes
        self.threads = threads
        self.stderr_limit = stderr_limit
        # Ayarlıysa exec anında bu AppArmor profiline geçiliyor. Geçiş
        # yapılamazsa iş başarısız oluyor: profil istenip de uygulanmaması
        # sessizce daha zayıf bir sandbox demek olurdu.
        self.apparmor_profile = apparmor_profile
        # İzin verilen syscall kümesi. Varsayılan ölçülmüş ffmpeg listesi;
        # gevşetmek yalnızca katmanları tek tek sınamak için anlamlı.
        self.syscalls = list(syscalls) if syscalls else list(seccomp.FFMPEG_SYSCALLS)


class Result:
    def __init__(self, output_path, output_bytes, elapsed_seconds, stderr):
        self.output_path = output_path
        self.output_bytes = output_bytes
        self.elapsed_seconds = elapsed_seconds
        self.stderr = stderr

    def __repr__(self):
        return (
            f"Result(output_path={self.output_path!r}, "
            f"output_bytes={self.output_bytes}, "
            f"elapsed_seconds={self.elapsed_seconds:.2f})"
        )


# --------------------------------------------------------------------------
# Yetenek denetimi
# --------------------------------------------------------------------------

# Ad alanı ve seccomp denemeleri süreç çatallıyor. İkisi de makinenin sabit
# bir özelliğini ölçtüğü için bir kez yapılıp saklanıyor: her istekte fork
# etmek, iş parçacıklı bir Flask işçisinde istenmeyecek bir şey.
_PROBE_CACHE = {}


def reset_probe_cache():
    """Saklanan yetenek ölçümlerini siler (testler için)."""
    _PROBE_CACHE.clear()


def _cached(key, probe):
    if key not in _PROBE_CACHE:
        _PROBE_CACHE[key] = probe()
    return _PROBE_CACHE[key]


def _probe_user_namespace():
    return _cached("userns", _probe_user_namespace_uncached)


def _probe_seccomp():
    return _cached("seccomp", _probe_seccomp_uncached)


def _probe_user_namespace_uncached():
    unshare = shutil.which("unshare")
    if unshare is None:
        return "unshare(1) bulunamadı (util-linux)"
    try:
        done = subprocess.run(
            [unshare, "--user", "--map-root-user", "--net", "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unshare çalıştırılamadı: {exc}"
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()
        return f"kullanıcı ad alanı açılamıyor: {detail or done.returncode}"
    return None


def _probe_seccomp_uncached():
    """Filtreyi ayrı bir süreçte kurup deneyerek sınar.

    Kurulum geri alınamaz olduğu için bu denemeyi asla çağıran sürecin
    kendisinde yapmıyoruz.
    """
    pid = os.fork()
    if pid == 0:
        try:
            seccomp.apply_ffmpeg_policy()
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return None
    return "seccomp filtresi kurulamıyor"


def check_capabilities(policy):
    """Eksik izolasyon katmanlarını döner. Boş liste = her şey hazır."""
    problems = []
    if sys.platform != "linux":
        problems.append(f"yalnızca Linux destekleniyor (bulunan: {sys.platform})")
        return problems
    if os.uname().machine != "x86_64":
        problems.append(
            f"seccomp tablosu x86_64'e özgü (bulunan: {os.uname().machine})"
        )
    if not os.path.isfile(policy.ffmpeg_path):
        problems.append(f"ffmpeg bulunamadı: {policy.ffmpeg_path}")
    namespace_problem = _probe_user_namespace()
    if namespace_problem:
        problems.append(namespace_problem)
    if policy.apparmor_profile and not apparmor_enabled():
        problems.append(
            f"AppArmor profili istendi ({policy.apparmor_profile}) ama "
            "çekirdekte AppArmor etkin değil"
        )
    if not problems:
        seccomp_problem = _probe_seccomp()
        if seccomp_problem:
            problems.append(seccomp_problem)
    return problems


# --------------------------------------------------------------------------
# 1. aşama: ad alanlarını aç, 2. aşamayı içeride çalıştır
# --------------------------------------------------------------------------

def transcode(input_path, output_path, *, profile="web-720p", policy=None):
    """Bir videoyu izole ortamda yeniden kodlar.

    Başarıda çıktıyı ``output_path``'e atomik olarak koyar. İzolasyon
    kurulamazsa ``SandboxError`` ile durur - ffmpeg çalıştırılmaz.
    """
    policy = policy or Policy()

    # Önce isteğin kendisi doğrulanıyor, sonra makinenin yetenekleri. Sıra
    # önemli: yetenek denemesi süreç çatallıyor, hatalı bir istek için
    # yapılmasına gerek yok - ve hata mesajı asıl soruna işaret ediyor.
    if profile not in PROFILES:
        raise SandboxError(f"bilinmeyen profil: {profile}")

    input_path = os.path.abspath(input_path)
    output_path = os.path.abspath(output_path)
    if not os.path.isfile(input_path):
        raise SandboxError(f"girdi dosyası yok: {input_path}")

    extension = os.path.splitext(output_path)[1].lower()
    allowed = PROFILE_EXTENSIONS[profile]
    if extension not in allowed:
        raise SandboxError(
            f"{profile} profili {sorted(allowed)} üretiyor, "
            f"istenen uzantı {extension or '(yok)'}"
        )
    demuxer = DEMUXER_BY_EXTENSION.get(os.path.splitext(input_path)[1].lower())
    if demuxer is None:
        raise SandboxError(f"desteklenmeyen girdi uzantısı: {input_path}")

    problems = check_capabilities(policy)
    if problems:
        raise SandboxError(
            "izolasyon kurulamıyor, ffmpeg çalıştırılmadı: " + "; ".join(problems)
        )

    # Hazırlık dizini çıktının yanında: os.replace aynı dosya sisteminde
    # atomik. app.py'deki save_videos ile aynı desen.
    staging_root = tempfile.mkdtemp(
        prefix=".sandbox-", dir=os.path.dirname(output_path) or "."
    )
    try:
        os.chmod(staging_root, 0o700)
        out_dir = os.path.join(staging_root, "out")
        os.mkdir(out_dir, 0o700)
        output_name = "output" + extension

        spec = {
            "ffmpeg": policy.ffmpeg_path,
            "input": input_path,
            "out_dir": out_dir,
            "argv": _build_argv(policy, profile, demuxer, output_name),
            "limits": {
                "memory_bytes": policy.memory_bytes,
                "cpu_seconds": policy.cpu_seconds,
                "max_output_bytes": policy.max_output_bytes,
                "max_open_files": policy.max_open_files,
            },
            "tmpfs_bytes": policy.tmpfs_bytes,
            "apparmor_profile": policy.apparmor_profile,
            "syscalls": policy.syscalls,
        }

        started = time.monotonic()
        completed = _run_stage2(spec, policy)
        elapsed = time.monotonic() - started

        stderr = completed.stderr.decode("utf-8", "replace")[: policy.stderr_limit]
        if completed.returncode != 0:
            raise TranscodeError(
                f"ffmpeg başarısız (çıkış {completed.returncode})",
                returncode=completed.returncode,
                stderr=stderr,
            )

        produced = _validate_output(out_dir, output_name, policy)
        os.replace(produced, output_path)
        os.chmod(output_path, 0o644)
        return Result(output_path, os.path.getsize(output_path), elapsed, stderr)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def _build_argv(policy, profile, demuxer, output_name):
    return [
        _FFMPEG_PATH,
        "-nostdin",
        "-hide_banner",
        "-nostats",
        "-loglevel", "error",
        # Tek bir tahsisin üst sınırı: şişirilmiş başlık alanlarıyla
        # tetiklenen dev tahsisleri kesiyor.
        "-max_alloc", str(policy.max_alloc_bytes),
        # file dışında protokol yok: concat:, http:, subfile: kapalı.
        "-protocol_whitelist", "file",
        # Demuxer'ı sabitle: içerik tahmini yok.
        "-f", demuxer,
        "-i", _IN_PATH,
        "-threads", str(policy.threads),
        *PROFILES[profile],
        "-y",
        f"{_OUT_DIR}/{output_name}",
    ]


def _run_stage2(spec, policy):
    package_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # -I: ortam değişkenlerini, site dizinlerini ve cwd'yi yok sayar. Bu
    # PYTHONPATH'i de yok saydığı için paketin yolunu açıkça veriyoruz -
    # ortam üzerinden vermek -I'yı kaldırmayı gerektirirdi.
    bootstrap = (
        "import sys, json\n"
        f"sys.path.insert(0, {package_parent!r})\n"
        "from sandbox.ffmpeg_sandbox import _stage2\n"
        "_stage2(json.loads(sys.argv[1]))\n"
    )
    command = [
        shutil.which("unshare"),
        "--user", "--map-root-user",
        "--mount", "--pid", "--fork", "--kill-child",
        "--net", "--ipc", "--uts",
        "--propagation", "private",
        "--",
        sys.executable, "-I", "-c", bootstrap, json.dumps(spec),
    ]
    # Ortam boşaltılıyor: LD_*, LANG ve benzeri değişkenler ffmpeg'in ve
    # altındaki kütüphanelerin davranışını değiştirebilir.
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
            timeout=policy.wall_clock_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # unshare --kill-child sayesinde unshare öldüğünde PID ad alanının
        # 1 numaralı süreci de ölüyor, o da içerideki her şeyi götürüyor.
        raise TranscodeError(
            f"ffmpeg {policy.wall_clock_seconds} saniyede bitmedi, öldürüldü",
            returncode=None,
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
        ) from exc


def _validate_output(out_dir, output_name, policy):
    entries = os.listdir(out_dir)
    if entries != [output_name]:
        raise TranscodeError(
            f"beklenmeyen çıktı içeriği: {sorted(entries)}"
        )
    produced = os.path.join(out_dir, output_name)
    if not os.path.isfile(produced) or os.path.islink(produced):
        raise TranscodeError("çıktı normal bir dosya değil")
    size = os.path.getsize(produced)
    if size == 0:
        raise TranscodeError("çıktı boş")
    if size > policy.max_output_bytes:
        raise TranscodeError(f"çıktı sınırı aştı: {size} bayt")
    return produced


# --------------------------------------------------------------------------
# 2. aşama: ad alanlarının içinde. Kök dosya sistemini kurar, sınırları
# koyar, seccomp filtresini yükler ve ffmpeg'e exec eder.
#
# Buradan sonra yeni modül import edilmiyor: pivot_root'tan sonra Python'ın
# kütüphane dizini görünmüyor, tembel bir import süreci öldürür.
# --------------------------------------------------------------------------

# libc bir kez, modül yüklenirken çözülüyor. ctypes.util.find_library Linux'ta
# ldconfig'i alt süreç olarak çalıştırıyor; bunu pivot_root'tan sonra ya da
# seccomp filtresi kurulduktan sonra yapmak kırılgan olurdu (ldconfig artık
# görünmüyor, fork zaten yasak). 2. aşamada geç bağlanan hiçbir şey kalmamalı.
_LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


def _libc():
    return _LIBC


def _mount(source, target, fstype, flags, data=None):
    libc = _libc()
    result = libc.mount(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        ctypes.c_ulong(flags),
        data.encode() if data else None,
    )
    if result != 0:
        errno = ctypes.get_errno()
        raise SandboxError(
            f"mount({source!r}, {target!r}, {fstype!r}) başarısız: "
            f"{os.strerror(errno)}"
        )


def _bind(source, target, extra_flags):
    if os.path.isdir(source):
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb"):
            pass
    _mount(source, target, None, MS_BIND | MS_REC)
    # Salt okunurluk ayrı bir remount gerektiriyor: ilk bind çağrısındaki
    # bayraklar yok sayılıyor. Bu iki adımlı yapı kolayca atlanıyor ve
    # sessizce yazılabilir bir bind bırakıyor.
    _mount(None, target, None, MS_REMOUNT | MS_BIND | extra_flags)


def _pivot_root(new_root, put_old):
    libc = _libc()
    result = libc.syscall(
        ctypes.c_long(_SYS_PIVOT_ROOT), new_root.encode(), put_old.encode()
    )
    if result != 0:
        raise OSError(ctypes.get_errno(), "pivot_root başarısız")


def _request_apparmor_profile(name):
    """Bir sonraki exec'te verilen AppArmor profiline geçilmesini ister.

    ``aa_change_onexec(3)``'ün dosya arayüzü. pivot_root'tan **önce**
    çağrılmalı: sonrasında /proc görünmüyor. İstek exec'e kadar bekliyor,
    dolayısıyla erken çağrılması sorun değil.

    Yazmanın başarılı dönmesi tek başına kanıt değil - ölçüldü: AppArmor
    hiç olmayan bir çekirdekte ``/proc/self/attr/exec`` yine duruyor ve
    yazma sessizce başarılı oluyor. O yüzden önce AppArmor'ın gerçekten
    etkin olduğunu doğruluyoruz; yoksa geçiş yapılmış gibi davranıp
    korumasız çalışırdık.
    """
    if not apparmor_enabled():
        return False
    payload = f"exec {name}"
    # AppArmor'a özgü yol varsa onu tercih et; genel LSM yolu başka bir LSM
    # tarafından da sahiplenilmiş olabilir.
    for path in ("/proc/self/attr/apparmor/exec", "/proc/self/attr/exec"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "w") as handle:
                handle.write(payload)
            return True
        except OSError:
            continue
    return False


def apparmor_enabled():
    """AppArmor çekirdekte etkin mi."""
    try:
        with open("/sys/module/apparmor/parameters/enabled") as handle:
            if handle.read().strip() in ("Y", "1"):
                return True
    except OSError:
        pass
    return os.path.isdir("/sys/kernel/security/apparmor")


def _stage2(spec):
    # AppArmor geçişi en başta: /proc'a hâlâ erişimimiz var.
    profile = spec.get("apparmor_profile")
    if profile and not _request_apparmor_profile(profile):
        raise SandboxError(
            f"AppArmor profiline geçilemedi ({profile}); ffmpeg çalıştırılmadı"
        )

    # Yayılımı özelleştir: aksi hâlde buradaki mount'lar ana makineye sızar.
    _mount(None, "/", None, MS_REC | MS_PRIVATE)

    new_root = tempfile.mkdtemp(prefix="mtsandbox-")
    _mount(
        "tmpfs", new_root, "tmpfs",
        MS_NOSUID | MS_NODEV,
        f"size={spec['tmpfs_bytes']},mode=0755",
    )

    # ffmpeg ikilisi: salt okunur. nosuid, no_new_privs'in yanında ikinci
    # bir güvence.
    _bind(spec["ffmpeg"], new_root + _FFMPEG_PATH, MS_RDONLY | MS_NOSUID | MS_NODEV)
    # Girdi: salt okunur ve çalıştırılamaz.
    _bind(
        spec["input"], new_root + _IN_PATH,
        MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
    )
    # Çıktı: yazılabilir tek yer, yine de çalıştırılamaz.
    _bind(spec["out_dir"], new_root + _OUT_DIR, MS_NOSUID | MS_NODEV | MS_NOEXEC)

    tmp_dir = os.path.join(new_root, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    _mount(
        "tmpfs", tmp_dir, "tmpfs",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        f"size={spec['tmpfs_bytes']},mode=0700",
    )

    old_root = os.path.join(new_root, ".oldroot")
    os.makedirs(old_root, exist_ok=True)

    # Kök artık salt okunur. Yazılabilir tek yerler /out ve /tmp (ikisi de
    # ayrı mount, ikisi de noexec). Bu olmadan /kacis.mp4 gibi bir yazma
    # sessizce "başarılı" oluyordu: veri hiçbir yere gitmiyordu ama
    # saldırgana yük bırakacak bir alan kalıyordu. Ölçüldü.
    _mount(None, new_root, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)

    try:
        _pivot_root(new_root, old_root)
        os.chdir("/")
        _libc().umount2(b"/.oldroot", MNT_DETACH)
        # rmdir salt okunur kökte başarısız olur; boş dizin zararsız.
        try:
            os.rmdir("/.oldroot")
        except OSError:
            pass
    except OSError:
        # pivot_root bazı mount düzenlerinde reddediliyor. chroot daha zayıf
        # (eski kök mount tablosunda kalıyor) ama ad alanları ve seccomp hâlâ
        # yerinde; sessizce sandbox'sız çalışmaktan iyi.
        os.chroot(new_root)
        os.chdir("/")

    limits = spec["limits"]
    resource.setrlimit(resource.RLIMIT_AS, (limits["memory_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["max_output_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits["max_open_files"],) * 2)
    # Çekirdek dökümü yok: çöken bir ffmpeg'in bellek görüntüsü girdinin
    # içeriğini çıktı dizinine düşürebilirdi.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    os.umask(0o077)
    seccomp.apply_ffmpeg_policy(spec.get("syscalls"))
    os.execve(_FFMPEG_PATH, spec["argv"], {"LC_ALL": "C"})


def main(argv=None):
    parser = argparse.ArgumentParser(description="ffmpeg sandbox")
    parser.add_argument("--stage2", help="iç aşama (elle çağrılmaz)")
    parser.add_argument("--check", action="store_true", help="yetenekleri sınar")
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--profile", default="web-720p")
    parser.add_argument("--ffmpeg")
    args = parser.parse_args(argv)

    if args.stage2:
        _stage2(json.loads(args.stage2))
        return 0  # execve döndüyse zaten hata

    policy = Policy(ffmpeg_path=args.ffmpeg)
    if args.check:
        problems = check_capabilities(policy)
        if problems:
            print("EKSİK:")
            for problem in problems:
                print("  -", problem)
            return 1
        print("Tüm izolasyon katmanları kullanılabilir.")
        return 0

    if not args.input or not args.output:
        parser.error("--input ve --output gerekli")
    result = transcode(args.input, args.output, profile=args.profile, policy=policy)
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
