"""C tarafının Python sarmalayıcısı.

İki şey sağlıyor:

* ``build_filter()`` - BPF programını C'de üretir. Python'daki uygulamayla
  **birebir aynı** baytları vermeli; testler bunu karşılaştırıyor. Amaç hız
  değil: elle yazılmış bir BPF birleştiricisinde sessiz bir hata (kayan bir
  etiket, sığmayan bir atlama) ya çalışan programı öldürür ya da izolasyonda
  delik bırakır, ve ikisi de normal testte kolayca gözden kaçar. İki bağımsız
  uygulamayı bayt bayt karşılaştırmak o sınıfı yakalıyor.

* ``exec_once_helper()`` - ``execve``'yi sayan çalıştırıcının yolu. Seccomp
  tek başına "ilkine izin ver, sonrakini reddet" diyemiyor; bu yardımcı
  SECCOMP_RET_USER_NOTIF ile o boşluğu kapatıyor.

**Derleme zorunlu değil.** C tarafı yoksa ya da derlenemiyorsa her şey
Python uygulamasına düşüyor; depo çalışma zamanında derleyici gerektirmiyor.
Yalnızca tek-exec kipi C olmadan çalışamıyor ve istendiğinde fail-closed
davranıyor.
"""

import ctypes
import hashlib
import os
import shutil
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SOURCES = ("mt_seccomp.c", "mt_exec_once.c", "mt_sweep.c",
            "mt_seccomp.h")

# Derleme çıktıları depoya girmiyor (.gitignore). Kaynakların özeti dizin
# adına giriyor: kaynak değişince eski çıktı kullanılmıyor.
_BUILD_ROOT = os.path.join(_HERE, "build")


class NativeError(Exception):
    """C tarafı derlenemedi ya da yüklenemedi."""


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _FilterSpec(ctypes.Structure):
    _fields_ = [
        ("allowed", ctypes.POINTER(ctypes.c_int)),
        ("n_allowed", ctypes.c_size_t),
        ("arch", ctypes.c_uint32),
        ("denied_action", ctypes.c_uint32),
        ("execve_action", ctypes.c_uint32),
        ("thread_only_clone", ctypes.c_int),
        ("nr_clone", ctypes.c_int),
        ("nr_clone3", ctypes.c_int),
        ("nr_fork", ctypes.c_int),
        ("nr_vfork", ctypes.c_int),
        ("nr_execve", ctypes.c_int),
        ("nr_execveat", ctypes.c_int),
    ]


def _source_digest():
    digest = hashlib.sha256()
    for name in sorted(_SOURCES):
        with open(os.path.join(_HERE, name), "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()[:16]


def build_dir():
    return os.path.join(_BUILD_ROOT, _source_digest())


def compiler():
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")


_build_cache = {}


def build(force=False):
    """C tarafını derler. ``(kütüphane, yardımcı)`` yollarını döner.

    Tembel ve önbellekli: kaynak özetine göre bir dizine üretiliyor, ikinci
    çağrı derlemiyor. Derleyici yoksa ``NativeError``.
    """
    key = _source_digest()
    if not force and key in _build_cache:
        return _build_cache[key]

    cc = compiler()
    if cc is None:
        raise NativeError("C derleyicisi bulunamadı (cc/gcc)")

    target = build_dir()
    library = os.path.join(target, "libmtseccomp.so")
    helper = os.path.join(target, "mt-exec-once")
    sweeper = os.path.join(target, "mt-sweep")
    artefacts = (library, helper, sweeper)
    if not force and all(os.path.exists(p) for p in artefacts):
        _build_cache[key] = artefacts
        return _build_cache[key]

    os.makedirs(target, exist_ok=True)
    common = [cc, "-O2", "-Wall", "-Wextra", "-I", _HERE]
    commands = [
        common + ["-fPIC", "-shared", "-o", library,
                  os.path.join(_HERE, "mt_seccomp.c")],
        # Yardımcı statik: sandbox kökünde paylaşımlı kütüphane bağlamak
        # gerekmesin, kök olabildiğince boş kalsın.
        common + ["-static", "-o", helper,
                  os.path.join(_HERE, "mt_exec_once.c"),
                  os.path.join(_HERE, "mt_seccomp.c")],
        common + ["-static", "-o", sweeper,
                  os.path.join(_HERE, "mt_sweep.c"),
                  os.path.join(_HERE, "mt_seccomp.c")],
    ]
    for command in commands:
        try:
            done = subprocess.run(command, capture_output=True, timeout=300)
        except (OSError, subprocess.SubprocessError) as error:
            # CC var olmayan bir yolu gösteriyorsa buraya düşüyor. Ham
            # FileNotFoundError sızdırmak, NativeError bekleyen çağıranın
            # onu kaçırması demek olurdu.
            raise NativeError(f"derleyici çalıştırılamadı: {error}") from error
        if done.returncode != 0:
            raise NativeError(
                "derleme başarısız: "
                + done.stderr.decode("utf-8", "replace").strip()[:2000]
            )
    _build_cache[key] = artefacts
    return _build_cache[key]


_library_cache = {}


def library():
    """Derlenmiş kütüphaneyi yükler."""
    path = build()[0]
    if path not in _library_cache:
        handle = ctypes.CDLL(path)
        handle.mt_build_filter.argtypes = [
            ctypes.POINTER(_FilterSpec),
            ctypes.POINTER(_SockFilter),
            ctypes.c_size_t,
        ]
        handle.mt_build_filter.restype = ctypes.c_int
        handle.mt_abi_version.restype = ctypes.c_int
        _library_cache[path] = handle
    return _library_cache[path]


def available():
    """C tarafı kullanılabilir mi. Hata fırlatmıyor."""
    try:
        library()
        return True
    except (NativeError, OSError):
        return False


def exec_once_helper():
    """Tek-exec çalıştırıcısının yolu."""
    return build()[1]


def sweeper():
    """Syscall tarayıcısının yolu."""
    return build()[2]


def abi_version():
    return library().mt_abi_version()


def build_filter(allowed_numbers, *, arch, denied_action, execve_action=0,
                 thread_only_clone=True, numbers):
    """BPF programını C'de üretir; ham baytları döner.

    ``numbers`` özel syscall numaralarını taşıyan sözlük (clone, clone3,
    fork, vfork, execve, execveat). Tek doğruluk kaynağı Python tarafındaki
    ölçülmüş tablo; C onu yeniden üretmiyor, parametre olarak alıyor.
    """
    handle = library()
    values = sorted(set(allowed_numbers))
    array = (ctypes.c_int * max(1, len(values)))(*values)
    spec = _FilterSpec(
        array, len(values), arch, denied_action, execve_action,
        1 if thread_only_clone else 0,
        numbers["clone"], numbers["clone3"], numbers["fork"],
        numbers["vfork"], numbers["execve"], numbers["execveat"],
    )
    out = (_SockFilter * 4096)()
    count = handle.mt_build_filter(ctypes.byref(spec), out, 4096)
    if count < 0:
        raise NativeError(f"mt_build_filter hata kodu {count}")
    return ctypes.string_at(ctypes.byref(out), count * 8)


def main(argv=None):
    """`python -m sandbox.native` - derler ve durumu yazar."""
    argv = sys.argv[1:] if argv is None else argv
    force = "--force" in argv
    try:
        library_path, helper_path, sweeper_path = build(force=force)
    except NativeError as error:
        print("C tarafı kullanılamıyor:", error)
        return 1
    print("kütüphane :", library_path)
    print("yardımcı  :", helper_path)
    print("tarayıcı  :", sweeper_path)
    print("ABI       :", abi_version())
    return 0


if __name__ == "__main__":
    sys.exit(main())
