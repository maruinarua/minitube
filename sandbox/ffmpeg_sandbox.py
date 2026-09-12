"""ffmpeg'i izole bir ad alanında çalıştıran politika katmanı.

İzolasyon motoru ``minisandbox``'ta; burada yalnızca ffmpeg'e özgü olan var:
hangi argümanların verileceği, hangi kapsayıcıların kabul edildiği ve
çıktının nasıl doğrulandığı.

Tehdit modeli: yüklenen video **düşman girdisidir**. libavcodec/libavformat
geniş bir ayrıştırıcı yüzeyi ve uzun bir bellek bozulması geçmişi taşıyor.
Varsayım şu: bir gün ffmpeg süreci içinde saldırganın kodu çalışacak.
``minisandbox`` katmanlarının hiçbiri bunu *önlemiyor*; hepsi o kodun ne
yapabileceğini daraltıyor.

Bu modülün kendi eklediği katman, bellek hatası bile gerektirmeyen bir
saldırı sınıfına karşı: ffmpeg'in playlist/concat özellikleri girdi
dosyasının başka dosyalara ve URL'lere referans vermesine izin veriyor, bu
da doğrudan yerel dosya okuma ve SSRF demek. ``-protocol_whitelist file`` ve
sabitlenmiş demuxer onu kapatıyor.

Ayrıntılı tasarım ve ölçümler için ``sandbox/README.md``.
"""

import argparse
import os
import shutil
import sys
import tempfile
import time

from . import minisandbox
from .minisandbox import SandboxError

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
# ("-i http://...", "-f lavfi -i ...", "-protocol_whitelist all") ve
# yukarıdaki katmanın üstünden atlar.
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
        self.ffmpeg_path = ffmpeg_path or os.environ.get(
            "FFMPEG_PATH", "/usr/bin/ffmpeg"
        )
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
        self.syscalls = list(syscalls) if syscalls else None

    def limits(self):
        return minisandbox.Limits(
            address_space_bytes=self.memory_bytes,
            cpu_seconds=self.cpu_seconds,
            file_size_bytes=self.max_output_bytes,
            open_files=self.max_open_files,
        )


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


def check_capabilities(policy):
    """Eksik izolasyon katmanlarını döner. Boş liste = her şey hazır."""
    problems = list(minisandbox.missing_capabilities(policy.apparmor_profile))
    if not os.path.isfile(policy.ffmpeg_path):
        problems.append(f"ffmpeg bulunamadı: {policy.ffmpeg_path}")
    return problems


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

        started = time.monotonic()
        completed = run_ffmpeg(
            _build_argv(policy, profile, demuxer, output_name),
            input_path, out_dir, policy,
        )
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


def run_ffmpeg(argv, input_path, out_dir, policy):
    """ffmpeg'i sandbox içinde çalıştırır. ``argv[0]`` sandbox içindeki yol.

    Testlerin katmanları tek tek sınayabilmesi için ayrı bir fonksiyon:
    ``transcode()`` sabit argümanlar üretiyor, bu ise verileni çalıştırıyor.
    """
    # Dinamik bağlanmış bir ffmpeg kendi kütüphanelerine ihtiyaç duyuyor;
    # statik olanda liste boş dönüyor ve kökte yalnızca ikili kalıyor.
    libraries = minisandbox.shared_libraries(policy.ffmpeg_path)
    try:
        return minisandbox.run(
            argv,
            ro_binds=[(policy.ffmpeg_path, _FFMPEG_PATH),
                      (input_path, _IN_PATH)] + libraries,
            rw_binds=[(out_dir, _OUT_DIR)],
            limits=policy.limits(),
            syscalls=policy.syscalls,
            tmpfs_bytes=policy.tmpfs_bytes,
            timeout=policy.wall_clock_seconds,
            apparmor_profile=policy.apparmor_profile,
        )
    except minisandbox.SandboxTimeout as exc:
        raise TranscodeError(str(exc), returncode=None, stderr="") from exc


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


def _validate_output(out_dir, output_name, policy):
    entries = os.listdir(out_dir)
    if entries != [output_name]:
        raise TranscodeError(f"beklenmeyen çıktı içeriği: {sorted(entries)}")
    produced = os.path.join(out_dir, output_name)
    if not os.path.isfile(produced) or os.path.islink(produced):
        raise TranscodeError("çıktı normal bir dosya değil")
    size = os.path.getsize(produced)
    if size == 0:
        raise TranscodeError("çıktı boş")
    if size > policy.max_output_bytes:
        raise TranscodeError(f"çıktı sınırı aştı: {size} bayt")
    return produced


def main(argv=None):
    parser = argparse.ArgumentParser(description="ffmpeg sandbox")
    parser.add_argument("--check", action="store_true", help="yetenekleri sınar")
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--profile", default="web-720p")
    parser.add_argument("--ffmpeg")
    args = parser.parse_args(argv)

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
    try:
        print(transcode(args.input, args.output,
                        profile=args.profile, policy=policy))
    except (SandboxError, TranscodeError) as exc:
        print("HATA:", exc, file=sys.stderr)
        stderr = getattr(exc, "stderr", "")
        if stderr:
            print(stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
