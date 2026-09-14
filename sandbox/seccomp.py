"""Seccomp-BPF filtresi üreten ve kuran küçük bir yardımcı.

Yalnızca stdlib kullanıyor: BPF programı burada elle kuruluyor ve
``prctl(PR_SET_SECCOMP)`` ctypes ile çağrılıyor. libseccomp bağlaması
(``seccomp`` / ``pyseccomp``) bilerek kullanılmıyor - depo Flask dışında
çalışma zamanı bağımlılığı taşımıyor ve izolasyon katmanının kendisi yeni
bir C bağımlılığı getirmemeli.

Filtre bir **izin listesi**: listede olmayan her syscall varsayılan olarak
süreci öldürüyor. Liste tahminle değil, gerçek bir ffmpeg koşusunun
``strace`` çıktısıyla belirlendi (bkz. README).

Seccomp'un yapamadığı şey: yol (path) denetimi. ``openat`` izinliyse
ffmpeg görebildiği her dosyayı açabilir. Neyi görebileceğini mount
ad alanı, neyi çalıştırabileceğini AppArmor sınırlıyor.
"""

import ctypes
import ctypes.util
import struct

# --- BPF komut kodları -----------------------------------------------------
_LD_W_ABS = 0x20  # BPF_LD | BPF_W | BPF_ABS
_JMP_JEQ_K = 0x15  # BPF_JMP | BPF_JEQ | BPF_K
_JMP_JGE_K = 0x35  # BPF_JMP | BPF_JGE | BPF_K
_JMP_JA = 0x05  # BPF_JMP | BPF_JA
_ALU_AND_K = 0x54  # BPF_ALU | BPF_AND | BPF_K
_RET_K = 0x06  # BPF_RET | BPF_K

# --- struct seccomp_data içindeki konumlar ---------------------------------
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG0_LO = 16  # args[0]'ın düşük 32 biti (little endian)

# --- seccomp dönüş eylemleri ----------------------------------------------
RET_KILL_PROCESS = 0x80000000
RET_TRAP = 0x00030000
RET_ERRNO = 0x00050000
RET_USER_NOTIF = 0x7FC00000
RET_LOG = 0x7FFC0000
RET_ALLOW = 0x7FFF0000

AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000

CLONE_THREAD = 0x00010000

EPERM = 1
ENOSYS = 38

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# x86_64 syscall numaraları. /usr/include/.../asm/unistd_64.h'dan alındı;
# çalışma zamanında başlık dosyası aramamak için sabitlendi.
SYSCALLS_X86_64 = {
    "read": 0, "write": 1, "close": 3, "stat": 4, "fstat": 5, "lstat": 6,
    "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
    "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20, "access": 21,
    "sched_yield": 24, "mremap": 25, "madvise": 28, "dup": 32, "dup2": 33,
    "nanosleep": 35, "getpid": 39, "clone": 56, "fork": 57, "vfork": 58,
    "execve": 59, "exit": 60, "uname": 63, "fcntl": 72, "fsync": 74,
    "ftruncate": 77, "getcwd": 79, "rename": 82, "mkdir": 83, "unlink": 87,
    "readlink": 89, "sysinfo": 99, "statfs": 137, "fstatfs": 138,
    "mlock": 149, "munlock": 150, "get_mempolicy": 239,
    "getuid": 102, "getgid": 104, "geteuid": 107,
    "execveat": 322, "getegid": 108, "getppid": 110, "getpgrp": 111, "sigaltstack": 131,
    "arch_prctl": 158, "gettid": 186,
    "time": 201, "futex": 202, "sched_getaffinity": 204, "getdents64": 217,
    "set_tid_address": 218, "restart_syscall": 219, "fadvise64": 221,
    "clock_gettime": 228, "clock_getres": 229, "clock_nanosleep": 230,
    "exit_group": 231, "tgkill": 234, "openat": 257, "newfstatat": 262,
    "unlinkat": 263, "faccessat": 269, "pselect6": 270, "ppoll": 271,
    "set_robust_list": 273, "eventfd2": 290, "dup3": 292, "pipe2": 293,
    "prlimit64": 302, "renameat2": 316, "getrandom": 318, "membarrier": 324,
    "statx": 332, "rseq": 334, "clone3": 435, "faccessat2": 439,
    "futex_waitv": 449, "prctl": 157, "getrusage": 98, "gettimeofday": 96,
    # Ağ syscall'ları. ffmpeg izin listesinde DEĞİLLER; burada tanımlı
    # olmalarının tek nedeni ağ ad alanını tek başına sınayabilmek
    # (bkz. NETWORK_SYSCALLS).
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
    "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49, "listen": 50,
    "getsockname": 51, "getpeername": 52, "socketpair": 53, "setsockopt": 54,
    "getsockopt": 55, "epoll_create1": 291, "epoll_ctl": 233, "epoll_wait": 232,
    "accept4": 288,
}

# Ağ ad alanının tek başına iş gördüğünü gösterebilmek için kullanılan
# gevşetilmiş küme. Üretimde kullanılmıyor: ffmpeg'in ağa çıkması için
# hiçbir meşru neden yok.
NETWORK_SYSCALLS = (
    "socket", "connect", "accept", "accept4", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
    "socketpair", "setsockopt", "getsockopt", "epoll_create1", "epoll_ctl",
    "epoll_wait",
)

# ffmpeg'in gerçekten çağırdığı syscall'lar. Tahmin değil: statik ffmpeg 7.0
# ile bir mp4 yeniden kodlaması `strace -f -c` altında koşturulup çıkan küme
# alındı, üstüne yalnızca kapanış/libc varyantları eklendi (exit_group,
# rt_sigreturn, newfstatat/statx gibi aynı işin farklı isimleri).
#
# Liste ffmpeg **yapısına** bağlı, sürümüne değil: Ubuntu 24.04'ün dinamik
# 6.1.1'i statik 7.0'ın hiç çağırmadığı üç şeyi çağırıyor ve üçü de SIGSYS
# ile öldürüyordu. Tek tek tahmin yerine reddetme eylemi geçici olarak
# RET_LOG yapılıp (kaydeder ama geçirir) tek koşuda tamamı ölçüldü.
#
# Listede bilerek OLMAYANLAR, saldırganın kod çalıştırsa bile
# kullanamayacakları: socket/connect/bind (ağ), fork/vfork (yeni süreç),
# ptrace (başka sürece girmek), mount/pivot_root/chroot, bpf,
# perf_event_open, userfaultfd (çekirdek açıklarında sık kullanılan
# yarış primitifi), keyctl/add_key, kexec_load, init_module, setuid ailesi,
# chmod/chown, process_vm_readv/writev.
FFMPEG_SYSCALLS = (
    # ölçülen küme
    "arch_prctl", "brk", "clock_gettime", "clone", "close", "execve", "fcntl",
    "fstat", "futex", "getrandom", "getrusage", "gettimeofday", "ioctl",
    "lseek", "madvise", "mmap", "mprotect", "munmap", "openat", "prctl",
    "prlimit64", "read", "readlink", "rt_sigaction", "rt_sigprocmask",
    "sched_getaffinity", "set_robust_list", "set_tid_address", "stat", "time",
    "uname", "write",
    # kapanış yolu ve libc varyantları
    "exit", "exit_group", "rt_sigreturn", "restart_syscall", "getpid", "gettid",
    "tgkill", "pread64", "pwrite64", "readv", "writev", "ppoll", "poll",
    "pselect6", "nanosleep", "clock_nanosleep", "clock_getres", "newfstatat",
    "statx", "lstat", "mremap", "rseq", "sched_yield", "membarrier",
    "getdents64", "dup", "dup2", "dup3", "pipe2", "eventfd2", "sigaltstack",
    "getuid", "geteuid", "getgid", "getegid", "fsync", "ftruncate", "unlink",
    "unlinkat", "access", "faccessat", "faccessat2", "getcwd", "fadvise64",
    "futex_waitv", "sysinfo",
    # Dağıtım yapılarının ek olarak istedikleri (Ubuntu 24.04, ffmpeg 6.1.1).
    # statfs/get_mempolicy yalnızca okuyor. mlock ise sayfaları belleğe
    # kilitliyor, yani tek gerçek maliyeti olan bu: sınırı seccomp değil
    # RLIMIT_MEMLOCK çiziyor ve minisandbox onu artık devralmak yerine
    # açıkça kuruyor (bkz. Limits.locked_memory_bytes).
    "statfs", "fstatfs", "get_mempolicy", "mlock", "munlock",
)


class SeccompError(Exception):
    """Filtre kurulamadı ya da üretilemedi."""


class _Assembler:
    """Etiket çözen küçük bir BPF birleştiricisi.

    Atlama uzaklıkları 8 bitlik; elle saymak yerine etiket kullanıp iki
    geçişte çözüyoruz. Uzaklık sığmazsa sessizce yanlış bir filtre
    üretmektense hata veriyor - yanlış filtre ya çalışan programı öldürür
    ya da izolasyonu delik bırakır.
    """

    def __init__(self):
        self._instructions = []
        self._labels = {}

    def label(self, name):
        if name in self._labels:
            raise SeccompError(f"etiket iki kez tanımlandı: {name}")
        self._labels[name] = len(self._instructions)

    def emit(self, code, jt=0, jf=0, k=0):
        self._instructions.append((code, jt, jf, k))

    def load(self, offset):
        self.emit(_LD_W_ABS, k=offset)

    def jeq(self, value, jt=0, jf=0):
        self.emit(_JMP_JEQ_K, jt, jf, value)

    def jge(self, value, jt=0, jf=0):
        self.emit(_JMP_JGE_K, jt, jf, value)

    def ja(self, target):
        self.emit(_JMP_JA, k=target)

    def and_(self, value):
        self.emit(_ALU_AND_K, k=value)

    def ret(self, action):
        self.emit(_RET_K, k=action)

    def assemble(self):
        if len(self._instructions) > 4096:
            raise SeccompError("BPF programı çekirdek sınırını (4096) aşıyor")
        out = bytearray()
        for index, (code, jt, jf, k) in enumerate(self._instructions):
            jt = self._resolve(jt, index)
            jf = self._resolve(jf, index)
            if code == _JMP_JA and isinstance(k, str):
                k = self._resolve(k, index, limit=0xFFFFFFFF)
            out += struct.pack("<HBBI", code, jt, jf, k)
        return bytes(out)

    def _resolve(self, target, index, limit=255):
        if not isinstance(target, str):
            return target
        if target not in self._labels:
            raise SeccompError(f"tanımsız etiket: {target}")
        offset = self._labels[target] - (index + 1)
        if offset < 0:
            raise SeccompError(f"geriye atlama BPF'te yasak: {target}")
        if offset > limit:
            raise SeccompError(
                f"atlama uzaklığı sığmıyor ({offset} > {limit}): {target}"
            )
        return offset


def build_filter(
    allowed_names,
    *,
    arch=AUDIT_ARCH_X86_64,
    syscalls=None,
    denied_action=RET_KILL_PROCESS,
    thread_only_clone=True,
    execve_action=None,
):
    """İzin listesinden BPF programı üretir.

    ``thread_only_clone`` açıkken ``clone`` yalnızca CLONE_THREAD bayrağıyla
    geçiyor. ffmpeg iş parçacığı açmak için clone çağırıyor; yeni *süreç*
    açmak için de aynı syscall kullanılıyor. Bayrağa bakmak ikisini
    ayırıyor: iş parçacığı serbest, çatallanma EPERM.

    ``clone3`` bilerek ENOSYS döndürüyor. Bayrakları bir yapı işaretçisiyle
    aldığı için seccomp içeriğine bakamıyor; ENOSYS görünce glibc eski
    ``clone``'a düşüyor ve bayrak denetimi yeniden mümkün oluyor. Ölçüldü:
    ENOSYS olmadan Python'ın iş parçacığı açması SIGSYS ile ölüyor.

    ``execve`` normalde izin listesinde kalmak zorunda - filtreyi exec'ten
    önce kuruyoruz, dolayısıyla hedefin kendisi de bu syscall'dan geçiyor.
    Seccomp tek başına "ilkine izin ver, sonrakini reddet" diyemiyor (sayaç
    yok). ``execve_action`` o boşluğu kapatmanın yolu: ``RET_USER_NOTIF``
    verildiğinde karar bir denetçi sürece bırakılıyor ve denetçi ilk exec'i
    geçirip kalanları reddediyor (bkz. sandbox/native/).

    ``execveat`` da aynı eylemi alıyor; yoksa doğrudan bir atlatma olurdu.
    """
    table = syscalls if syscalls is not None else SYSCALLS_X86_64
    unknown = [name for name in allowed_names if name not in table]
    if unknown:
        raise SeccompError(f"bilinmeyen syscall adı: {', '.join(sorted(unknown))}")

    clone_nr = table.get("clone")
    clone3_nr = table.get("clone3")
    # fork ve vfork'un bayrağı yok: her zaman yeni bir süreç demek, yani
    # koşulsuz reddediliyorlar. Öldürmek yerine EPERM, clone ile tutarlı
    # olsun diye - aynı niyetin (süreç açmak) libc'nin hangi syscall'ı
    # seçtiğine göre bir öldürme bir hata dönmesi kafa karıştırıcıydı.
    # Demoda görüldü: kabuk fork çağırınca betik ortasında SIGSYS ile
    # ölüyordu, clone çağırsa "cannot fork" deyip devam edecekti.
    fork_numbers = [
        table[name] for name in ("fork", "vfork") if name in table
    ] if thread_only_clone else []
    special = {clone_nr, clone3_nr, *fork_numbers} if thread_only_clone else set()
    exec_numbers = []
    if execve_action is not None:
        exec_numbers = [table[n] for n in ("execve", "execveat") if n in table]
        special = special | set(exec_numbers)
    numbers = sorted({table[name] for name in allowed_names} - special)

    asm = _Assembler()

    # Mimari uyuşmuyorsa hiç devam etme: syscall numaraları mimariye göre
    # değişiyor, yanlış mimaride "izin verilen 59" bambaşka bir çağrı olur.
    asm.load(_OFF_ARCH)
    asm.jeq(arch, jt=0, jf="kill")

    # x32 ABI aynı numaraları 0x40000000 bitiyle çağırıyor; filtreyi atlatmak
    # için kullanılabilir, o yüzden komple kapatıyoruz.
    asm.load(_OFF_NR)
    asm.jge(_X32_SYSCALL_BIT, jt="kill", jf=0)

    if thread_only_clone and clone_nr is not None:
        asm.jeq(clone_nr, jt="clone_check", jf=0)
    if thread_only_clone and clone3_nr is not None:
        asm.jeq(clone3_nr, jt="clone3_enosys", jf=0)
    for number in fork_numbers:
        asm.jeq(number, jt="deny_clone", jf=0)
    for number in exec_numbers:
        asm.jeq(number, jt="exec_action", jf=0)

    for number in numbers:
        asm.jeq(number, jt="allow", jf=0)
    asm.ja("deny")

    if thread_only_clone and clone_nr is not None:
        asm.label("clone_check")
        asm.load(_OFF_ARG0_LO)
        asm.and_(CLONE_THREAD)
        asm.jeq(CLONE_THREAD, jt="allow", jf="deny_clone")
        asm.label("deny_clone")
        asm.ret(RET_ERRNO | EPERM)
    if thread_only_clone and clone3_nr is not None:
        asm.label("clone3_enosys")
        asm.ret(RET_ERRNO | ENOSYS)
    if exec_numbers:
        asm.label("exec_action")
        asm.ret(execve_action)

    asm.label("allow")
    asm.ret(RET_ALLOW)
    asm.label("deny")
    asm.ret(denied_action)
    asm.label("kill")
    asm.ret(RET_KILL_PROCESS)

    return asm.assemble()


def _libc():
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)


def set_no_new_privs():
    """Sonraki exec'lerin ayrıcalık kazanmasını kalıcı olarak engeller.

    Seccomp filtresi kurabilmek için de zorunlu (root değilsek). Ayrıca
    setuid bir ikiliye exec edilse bile ayrıcalık verilmemesini garanti
    ediyor.
    """
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompError(
            f"PR_SET_NO_NEW_PRIVS başarısız: {ctypes.get_errno()}"
        )


def install(program):
    """BPF programını mevcut sürece kurar. Geri alınamaz."""
    if len(program) % 8 != 0 or not program:
        raise SeccompError("geçersiz BPF programı")

    class _SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    libc = _libc()
    buffer_ = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // 8, ctypes.cast(buffer_, ctypes.c_void_p))
    result = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0)
    # buffer_ referansı prctl dönene kadar canlı kalmalı; çekirdek programı
    # çağrı sırasında kendi belleğine kopyalıyor.
    del buffer_
    if result != 0:
        raise SeccompError(f"PR_SET_SECCOMP başarısız: {ctypes.get_errno()}")


def apply_ffmpeg_policy(allowed_names=None, denied_action=RET_KILL_PROCESS):
    """ffmpeg için ölçülmüş izin listesini kurar."""
    set_no_new_privs()
    names = FFMPEG_SYSCALLS if allowed_names is None else allowed_names
    install(build_filter(names, denied_action=denied_action))
