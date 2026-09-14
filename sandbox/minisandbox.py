"""Minimal Linux namespace sandbox - sıfır bağımlılık.

Yalnızca standart kütüphane: ``subprocess`` (util-linux'un ``unshare``
komutunu çağırmak için), ``ctypes`` (mount/pivot_root syscall'ları) ve
``resource``. Üçüncü parti paket, libseccomp bağlaması, konteyner çalışma
zamanı yok. Kurulum gerektirmiyor: ayrıcalıksız kullanıcı ad alanı açık olan
her Linux'ta çalışıyor.

Bu modül **ffmpeg'den bağımsız**. Herhangi bir komutu izole bir ad alanında
çalıştırıyor; ``ffmpeg_sandbox`` bunun üstüne kodlamaya özgü politikayı
koyuyor. Ayrılmasının pratik bir nedeni var: motor böylece ffmpeg kurulu
olmayan bir makinede de (örneğin CI koşucusunda) sınanabiliyor.

Ne veriyor:

* user + mount + pid + net + ipc + uts ad alanları
* tmpfs üzerine kurulu, **salt okunur** minimal kök
* yalnızca açıkça verilen yollar görünür; ağ ad alanı boş
* seccomp izin listesi (bkz. ``seccomp.py``)
* RLIMIT'ler ve duvar saati sınırı
* isteğe bağlı AppArmor profil geçişi

Ne vermiyor: bu bir konteyner çalışma zamanı değil. Cgroup yok, kullanıcı
eşleme aralığı yok, imaj yönetimi yok. Çekirdek hâlâ saldırı yüzeyi.

Deneme:

    python -m sandbox.minisandbox --demo
"""

import argparse
import ctypes
import ctypes.util
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

from . import native
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

# Tek-exec kipinde sandbox içindeki sabit yollar.
_HELPER_PATH = "/mt-exec-once"
_POLICY_PATH = "/policy.bpf"

# Minimal /dev. Bunlar olmadan "2>/dev/null" gibi çok yaygın bir deyim
# çalışmıyor - demo bunu yakaladı: kabuk yönlendirmeyi kuramayınca komut
# başarısız oluyor ve sandbox'ın kendisi suçlu görünüyor.
#
# Dikkat: bu bağlamalarda MS_NODEV **yok**. Olsaydı çekirdek aygıt
# semantiğini yok sayar ve /dev/null sıradan bir dosya gibi davranırdı.
# MS_RDONLY de yok: /dev/null'a yazmak gerekiyor.
DEFAULT_DEV_NODES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/urandom",
                     "/dev/random")

# libc bir kez, modül yüklenirken çözülüyor. ctypes.util.find_library Linux'ta
# ldconfig'i alt süreç olarak çalıştırıyor; bunu pivot_root'tan ya da seccomp
# filtresinden sonra yapmak kırılgan olurdu (ldconfig artık görünmüyor, fork
# zaten yasak). 2. aşamada geç bağlanan hiçbir şey kalmamalı.
_LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
_LIBC.syscall.restype = ctypes.c_long


class SandboxError(Exception):
    """Sandbox kurulamadı ya da kurallara uyulmadı."""


class SandboxTimeout(SandboxError):
    """Komut süre sınırını aştı ve öldürüldü."""


class Limits:
    """Süreç kaynak sınırları.

    ``address_space_bytes`` RLIMIT_AS'e gidiyor, yani *sanal adres alanını*
    sınırlıyor - gerçek kullanımı değil. Modern ayırıcılar cömert rezervasyon
    yaptığı için ikisi arasındaki fark büyük olabiliyor; gerçek bellek tavanı
    isteniyorsa doğru araç cgroup ``memory.max``.
    """

    def __init__(
        self,
        address_space_bytes=2 * 1024 * 1024 * 1024,
        cpu_seconds=120,
        file_size_bytes=512 * 1024 * 1024,
        open_files=64,
        locked_memory_bytes=64 * 1024 * 1024,
    ):
        self.address_space_bytes = address_space_bytes
        self.cpu_seconds = cpu_seconds
        self.file_size_bytes = file_size_bytes
        self.open_files = open_files
        # mlock izin listesinde, dolayısıyla kilitlenebilecek bellek
        # sınırlanmalı. Devralınan değere bırakmak olmaz: bu makinede 8 MiB
        # geliyor ama kap yapılandırmasına göre sınırsız da olabiliyor.
        self.locked_memory_bytes = locked_memory_bytes

    def as_dict(self):
        return {
            "address_space_bytes": self.address_space_bytes,
            "cpu_seconds": self.cpu_seconds,
            "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
            "locked_memory_bytes": self.locked_memory_bytes,
        }


def _normalise_binds(binds):
    """``"/yol"`` ya da ``("/host", "/icerideki")`` girdilerini çifte çevirir.

    Varsayılan olarak yol korunuyor. Dinamik bağlanmış ikililer için bu şart:
    ELF yorumlayıcısının yolu (``/lib64/ld-linux-x86-64.so.2``) ikilinin
    içine gömülü, başka bir yere bağlanırsa süreç hiç başlamıyor.
    """
    pairs = []
    for entry in binds:
        if isinstance(entry, (tuple, list)):
            source, target = entry
        else:
            source, target = entry, entry
        if not os.path.isabs(target):
            raise SandboxError(f"sandbox içindeki yol mutlak olmalı: {target}")
        pairs.append((os.path.abspath(source), target))
    return pairs


# --------------------------------------------------------------------------
# Yetenek denetimi
# --------------------------------------------------------------------------

# Ad alanı ve seccomp denemeleri süreç çatallıyor. İkisi de makinenin sabit
# bir özelliğini ölçtüğü için bir kez yapılıp saklanıyor: her çağrıda fork
# etmek, iş parçacıklı bir sunucu sürecinde istenmeyecek bir şey.
_PROBE_CACHE = {}


def reset_probe_cache():
    """Saklanan yetenek ölçümlerini siler (testler için)."""
    _PROBE_CACHE.clear()


def _cached(key, probe):
    if key not in _PROBE_CACHE:
        _PROBE_CACHE[key] = probe()
    return _PROBE_CACHE[key]


def probe_user_namespace():
    return _cached("userns", _probe_user_namespace_uncached)


def probe_seccomp():
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


def apparmor_enabled():
    """AppArmor çekirdekte etkin mi."""
    try:
        with open("/sys/module/apparmor/parameters/enabled") as handle:
            if handle.read().strip() in ("Y", "1"):
                return True
    except OSError:
        pass
    return os.path.isdir("/sys/kernel/security/apparmor")


def missing_capabilities(apparmor_profile=None):
    """Eksik izolasyon katmanlarını döner. Boş liste = her şey hazır."""
    problems = []
    if sys.platform != "linux":
        return [f"yalnızca Linux destekleniyor (bulunan: {sys.platform})"]
    if os.uname().machine != "x86_64":
        problems.append(
            f"seccomp tablosu x86_64'e özgü (bulunan: {os.uname().machine})"
        )
    namespace_problem = probe_user_namespace()
    if namespace_problem:
        problems.append(namespace_problem)
    if not problems:
        seccomp_problem = probe_seccomp()
        if seccomp_problem:
            problems.append(seccomp_problem)
    if apparmor_profile and not apparmor_enabled():
        problems.append(
            f"AppArmor profili istendi ({apparmor_profile}) ama çekirdekte "
            "AppArmor etkin değil"
        )
    return problems


def shared_libraries(executable):
    """Dinamik bağlanmış bir ikilinin ihtiyaç duyduğu kütüphane yolları.

    ``ldd`` çıktısını ayrıştırıyor. Statik ikililerde boş liste dönüyor -
    en temiz durum, kökte yalnızca ikilinin kendisi oluyor. ``ldd`` yoksa
    ya da çıktı anlaşılmazsa ``SandboxError``: eksik kütüphaneyle sandbox
    kurup "komut çalışmadı" demek, sorunu izolasyona yıkmak olurdu.
    """
    ldd = shutil.which("ldd")
    if ldd is None:
        raise SandboxError("ldd bulunamadı; kütüphaneleri elle verin")
    done = subprocess.run([ldd, executable], capture_output=True, timeout=30)
    if done.returncode != 0:
        return []  # statik ikili: "not a dynamic executable"
    paths = []
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if "=>" in line:
            candidate = line.split("=>", 1)[1].strip().split(" ")[0]
        else:
            candidate = line.split(" ")[0]
        if candidate.startswith("/") and os.path.exists(candidate):
            paths.append(candidate)
    return paths


# --------------------------------------------------------------------------
# 1. aşama: ad alanlarını aç, 2. aşamayı içeride çalıştır
# --------------------------------------------------------------------------

def run(
    argv,
    *,
    ro_binds=(),
    rw_binds=(),
    limits=None,
    syscalls=None,
    tmpfs_bytes=64 * 1024 * 1024,
    dev_nodes=DEFAULT_DEV_NODES,
    timeout=180,
    apparmor_profile=None,
    single_exec=False,
    env=None,
    workdir="/",
    check_capabilities=True,
):
    """``argv``'yi izole bir ad alanında çalıştırır.

    ``argv[0]`` sandbox **içindeki** yol. O yolu görünür kılmak çağıranın
    işi: çalıştırılacak ikiliyi ``ro_binds``'a koyun (varsayılan olarak aynı
    yola bağlanır).

    İzolasyon katmanları kurulamıyorsa komut **hiç çalıştırılmıyor** -
    korumasız çalıştırmak en kötü sonuç olurdu.
    """
    limits = limits or Limits()
    if check_capabilities:
        problems = missing_capabilities(apparmor_profile)
        if single_exec and not native.available():
            # Fail-closed: tek-exec kipi istenip de kurulamıyorsa komutu
            # zayıf bir filtreyle çalıştırmak sessizce daha az koruma olurdu.
            problems.append(
                "tek-exec kipi istendi ama C tarafı derlenemedi "
                "(derleyici gerekiyor)"
            )
        if problems:
            raise SandboxError(
                "izolasyon kurulamıyor, komut çalıştırılmadı: "
                + "; ".join(problems)
            )

    extra_ro = []
    policy_handle = None
    if single_exec:
        # Yardımcı ve politika dosyası sandbox içine bağlanıyor. BPF'i burada
        # üretip dosyaya yazıyoruz: yardımcı onu olduğu gibi kuruyor, yani
        # filtrenin tek doğruluk kaynağı yine Python tarafı.
        program = seccomp.build_filter(
            list(syscalls) if syscalls else list(seccomp.FFMPEG_SYSCALLS),
            execve_action=seccomp.RET_USER_NOTIF,
        )
        policy_handle = tempfile.NamedTemporaryFile(
            prefix="mt-policy-", suffix=".bpf", delete=False
        )
        policy_handle.write(program)
        policy_handle.flush()
        policy_handle.close()
        extra_ro = [
            (native.exec_once_helper(), _HELPER_PATH),
            (policy_handle.name, _POLICY_PATH),
        ]

    spec = {
        "argv": list(argv),
        "ro_binds": _normalise_binds(list(ro_binds) + extra_ro),
        "rw_binds": _normalise_binds(rw_binds),
        "limits": limits.as_dict(),
        "tmpfs_bytes": tmpfs_bytes,
        "dev_nodes": [p for p in (dev_nodes or ()) if os.path.exists(p)],
        "apparmor_profile": apparmor_profile,
        "syscalls": list(syscalls) if syscalls else list(seccomp.FFMPEG_SYSCALLS),
        "single_exec": bool(single_exec),
        "env": dict(env) if env else {"LC_ALL": "C"},
        "workdir": workdir,
    }

    package_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # -I: ortam değişkenlerini, site dizinlerini ve cwd'yi yok sayar. Bu
    # PYTHONPATH'i de yok saydığı için paketin yolunu açıkça veriyoruz -
    # ortam üzerinden vermek -I'yı kaldırmayı gerektirirdi.
    bootstrap = (
        "import sys, json\n"
        f"sys.path.insert(0, {package_parent!r})\n"
        "from sandbox.minisandbox import _stage2\n"
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
    # start_new_session + grup öldürme: zaman aşımında yalnızca unshare'i
    # değil, altındaki her şeyi götürmek için.
    #
    # Buna somut bir gözlem yol açtı: önceki sürümde zaman aşımı testi her
    # koşuda meşgul döngüdeki yükü geride bırakıyordu - ana makinede PID 1'e
    # evlat edinilmiş, CPU yakmaya devam eder hâlde. "Öldürdüm" sanılan işin
    # çalışmaya devam etmesi bir sandbox için kabul edilemez.
    #
    # Dürüst not: hangi değişikliğin tek başına yettiğini izole edemedim -
    # kısmi geri almalarla sızıntıyı yeniden üretemedim. O yüzden burada
    # "unshare --kill-child bozuk" gibi bir iddia yok; yalnızca istenen
    # davranış açıkça kuruluyor ve regresyon testiyle korunuyor
    # (test_timeout_leaves_no_surviving_process).
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # Ortam boşaltılıyor: LD_*, LANG ve benzeri değişkenler
        # çalıştırılan programın davranışını değiştirebilir.
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise SandboxTimeout(
            f"komut {timeout} saniyede bitmedi, öldürüldü"
        ) from None
    finally:
        if policy_handle is not None:
            try:
                os.unlink(policy_handle.name)
            except OSError:
                pass
    return subprocess.CompletedProcess(
        command, process.returncode, stdout, stderr
    )


def _kill_process_group(process):
    """Sürecin grubunu komple SIGKILL'ler, olmazsa sürecin kendisini."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


# --------------------------------------------------------------------------
# 2. aşama: ad alanlarının içinde. Kök dosya sistemini kurar, sınırları
# koyar, seccomp filtresini yükler ve hedefe exec eder.
#
# Buradan sonra yeni modül import edilmiyor: pivot_root'tan sonra Python'ın
# kütüphane dizini görünmüyor, tembel bir import süreci öldürür.
# --------------------------------------------------------------------------

def _mount(source, target, fstype, flags, data=None):
    result = _LIBC.mount(
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
    result = _LIBC.syscall(
        ctypes.c_long(_SYS_PIVOT_ROOT), new_root.encode(), put_old.encode()
    )
    if result != 0:
        raise OSError(ctypes.get_errno(), "pivot_root başarısız")


def _request_apparmor_profile(name):
    """Bir sonraki exec'te verilen AppArmor profiline geçilmesini ister.

    ``aa_change_onexec(3)``'ün dosya arayüzü. pivot_root'tan **önce**
    çağrılmalı: sonrasında /proc görünmüyor.

    Yazmanın başarılı dönmesi tek başına kanıt değil - ölçüldü: AppArmor
    hiç olmayan bir çekirdekte ``/proc/self/attr/exec`` yine duruyor ve
    yazma sessizce başarılı oluyor. O yüzden önce AppArmor'ın gerçekten
    etkin olduğunu doğruluyoruz.
    """
    if not apparmor_enabled():
        return False
    payload = f"exec {name}"
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


def _stage2(spec):
    # AppArmor geçişi en başta: /proc'a hâlâ erişimimiz var.
    profile = spec.get("apparmor_profile")
    if profile and not _request_apparmor_profile(profile):
        raise SandboxError(
            f"AppArmor profiline geçilemedi ({profile}); komut çalıştırılmadı"
        )

    # Yayılımı özelleştir: aksi hâlde buradaki mount'lar ana makineye sızar.
    _mount(None, "/", None, MS_REC | MS_PRIVATE)

    new_root = tempfile.mkdtemp(prefix="minisandbox-")
    _mount(
        "tmpfs", new_root, "tmpfs",
        MS_NOSUID | MS_NODEV,
        f"size={spec['tmpfs_bytes']},mode=0755",
    )

    for source, target in spec["ro_binds"]:
        _bind(source, new_root + target, MS_RDONLY | MS_NOSUID | MS_NODEV)
    for source, target in spec["rw_binds"]:
        # Yazılabilir ama çalıştırılamaz: saldırgan buraya yük bıraksa bile
        # çalıştıramıyor.
        _bind(source, new_root + target, MS_NOSUID | MS_NODEV | MS_NOEXEC)

    for node in spec.get("dev_nodes", ()):
        # MS_NODEV ve MS_RDONLY bilerek yok - yukarıdaki nota bakın.
        _bind(node, new_root + node, MS_NOSUID | MS_NOEXEC)

    tmp_dir = os.path.join(new_root, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    _mount(
        "tmpfs", tmp_dir, "tmpfs",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        f"size={spec['tmpfs_bytes']},mode=0700",
    )

    old_root = os.path.join(new_root, ".oldroot")
    os.makedirs(old_root, exist_ok=True)

    # Kök artık salt okunur. Yazılabilir tek yerler rw_binds ve /tmp (hepsi
    # noexec). Bu olmadan kökün herhangi bir yerine yazma sessizce
    # "başarılı" oluyordu: veri hiçbir yere gitmiyordu ama saldırgana yük
    # bırakacak alan kalıyordu. Ölçüldü.
    _mount(None, new_root, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)

    try:
        _pivot_root(new_root, old_root)
        os.chdir("/")
        _LIBC.umount2(b"/.oldroot", MNT_DETACH)
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

    try:
        os.chdir(spec["workdir"])
    except OSError:
        os.chdir("/")

    limits = spec["limits"]
    resource.setrlimit(resource.RLIMIT_AS, (limits["address_space_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["file_size_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits["open_files"],) * 2)
    # Yalnızca düşürüyoruz: sert sınırı yükseltmek ana ad alanında
    # CAP_SYS_RESOURCE istiyor ve burada yok - denemek ValueError veriyor.
    # Devralınan değer zaten istenenden düşükse o daha sıkıdır, dokunma.
    _memlock_hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)[1]
    _memlock = limits["locked_memory_bytes"]
    if _memlock_hard != resource.RLIM_INFINITY:
        _memlock = min(_memlock, _memlock_hard)
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (_memlock,) * 2)
    # Çekirdek dökümü yok: çöken bir sürecin bellek görüntüsü girdinin
    # içeriğini yazılabilir bir dizine düşürebilirdi.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    os.umask(0o077)
    if spec.get("single_exec"):
        # Filtreyi yardımcı kuruyor: NEW_LISTENER ile kurup denetçiyi
        # fork etmesi gerekiyor ve fork, filtre kurulduktan sonra yasak.
        # Sıra bu yüzden yardımcının içinde.
        argv = [_HELPER_PATH, _POLICY_PATH] + list(spec["argv"])
        os.execve(_HELPER_PATH, argv, spec["env"])
    seccomp.apply_ffmpeg_policy(spec["syscalls"])
    os.execve(spec["argv"][0], spec["argv"], spec["env"])


# --------------------------------------------------------------------------
# Gösterim
# --------------------------------------------------------------------------

# Betikte bilerek ne alt kabuk ($(...)) ne de harici komut var: ikisi de
# fork gerektiriyor ve fork seccomp tarafından engelleniyor. Yani bu betiğin
# şekli de bir gösterim - sandbox içinde yardımcı süreç çalıştırılamıyor.
_DEMO_SCRIPT = r"""
if echo x > /kacis 2>/dev/null; then
  echo "  kök yazılabilir       : EVET (beklenmedik)"
else
  echo "  kök yazılabilir       : hayır"
fi
if [ -r /etc/passwd ]; then
  echo "  /etc/passwd           : EVET (beklenmedik)"
else
  echo "  /etc/passwd           : görünmüyor"
fi
if [ -d /home ]; then
  echo "  /home                 : EVET (beklenmedik)"
else
  echo "  /home                 : görünmüyor"
fi
if [ -d /proc/1 ]; then
  echo "  /proc                 : EVET (beklenmedik)"
else
  echo "  /proc                 : görünmüyor"
fi
if echo veri > /out/dosya 2>/dev/null; then
  echo "  /out yazılabilir      : evet (beklenen)"
else
  echo "  /out yazılabilir      : HAYIR (beklenmedik)"
fi
"""

# Ayrı koşu: kabuk yardımcı süreç açamayınca ölümcül hata verip çıkıyor, yani
# bu denemeyi yukarıdaki betiğin içine koymak kalan satırları bastırırdı.
_FORK_SCRIPT = "/bin/true; echo 'yardımcı süreç açıldı'"


def _demo():
    """Hiçbir şey kurmadan sandbox'ı gösterir.

    Yük olarak sistemin kendi kabuğu kullanılıyor; tek ihtiyacı libc ve ELF
    yükleyicisi. ffmpeg ya da başka bir paket gerekmiyor.
    """
    problems = missing_capabilities()
    if problems:
        print("Bu makinede sandbox kurulamıyor:")
        for problem in problems:
            print("  -", problem)
        return 1

    shell = os.path.realpath(shutil.which("sh") or "/bin/sh")
    libraries = shared_libraries(shell)
    # Kabuğun syscall kümesi strace ile ölçüldü: ffmpeg'inkiyle neredeyse
    # aynı, tek fark getppid.
    shell_syscalls = list(seccomp.FFMPEG_SYSCALLS) + ["getppid"]
    print(f"Yük: {shell}")
    print(f"Gereken kütüphaneler ({len(libraries)}): "
          + ", ".join(os.path.basename(p) for p in libraries))

    out_dir = tempfile.mkdtemp(prefix="minisandbox-demo-")
    try:
        print("\nSandbox içinden görünen:")
        done = run(
            [shell, "-c", _DEMO_SCRIPT],
            ro_binds=[shell] + libraries,
            rw_binds=[(out_dir, "/out")],
            syscalls=shell_syscalls,
            timeout=60,
        )
        sys.stdout.write(done.stdout.decode("utf-8", "replace"))
        if done.stderr:
            sys.stdout.write(done.stderr.decode("utf-8", "replace"))
        print(f"\n  kabuk çıkış kodu     : {done.returncode}")

        forked = run(
            [shell, "-c", _FORK_SCRIPT],
            ro_binds=[shell] + libraries,
            syscalls=shell_syscalls,
            timeout=60,
        )
        spawned = b"yard" in forked.stdout
        reason = forked.stderr.decode("utf-8", "replace").strip().split(":")[-1]
        print(f"  yardımcı süreç açıldı: {'EVET (beklenmedik)' if spawned else 'hayır'}"
              f" ({reason.strip() or 'sessiz'})")
        print(f"  ana makinede /kacis  : {os.path.exists('/kacis')}")
        print(f"  /out içeriği         : {sorted(os.listdir(out_dir))}")

        # Ağ: seccomp'u gevşetip ad alanını tek başına gösteriyoruz.
        relaxed = shell_syscalls + list(seccomp.NETWORK_SYSCALLS)
        net = run(
            [shell, "-c", "exec 3<>/dev/tcp/127.0.0.1/22 && echo ACIK || echo kapali"],
            ro_binds=[shell] + libraries,
            syscalls=relaxed,
            timeout=60,
        )
        detail = net.stdout.decode("utf-8", "replace").strip()
        print(f"  127.0.0.1:22 (ağ)    : {detail or 'bağlanamadı'}")
        return 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Minimal Linux namespace sandbox (yalnızca stdlib)"
    )
    parser.add_argument("--demo", action="store_true",
                        help="hiçbir şey kurmadan izolasyonu gösterir")
    parser.add_argument("--check", action="store_true",
                        help="izolasyon katmanlarını sınar")
    parser.add_argument("--ro", action="append", default=[],
                        help="salt okunur bağlanacak yol (tekrarlanabilir)")
    parser.add_argument("--rw", action="append", default=[],
                        help="yazılabilir bağlanacak yol (tekrarlanabilir)")
    parser.add_argument("--with-libs", action="store_true",
                        help="komutun paylaşımlı kütüphanelerini de bağla")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("command", nargs="*", help="çalıştırılacak komut")
    args = parser.parse_args(argv)

    if args.demo:
        return _demo()

    if args.check:
        problems = missing_capabilities()
        if problems:
            print("EKSİK:")
            for problem in problems:
                print("  -", problem)
            return 1
        print("Tüm izolasyon katmanları kullanılabilir.")
        return 0

    if not args.command:
        parser.error("çalıştırılacak bir komut verin (ya da --demo)")

    executable = os.path.realpath(args.command[0])
    ro_binds = [executable] + list(args.ro)
    if args.with_libs:
        ro_binds += shared_libraries(executable)
    done = run(
        [executable] + args.command[1:],
        ro_binds=ro_binds,
        rw_binds=args.rw,
        timeout=args.timeout,
    )
    sys.stdout.write(done.stdout.decode("utf-8", "replace"))
    sys.stderr.write(done.stderr.decode("utf-8", "replace"))
    return done.returncode


if __name__ == "__main__":
    sys.exit(main())
