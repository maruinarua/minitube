"""ffmpeg sandbox testleri.

İki kısım var:

* **Filtre ve politika testleri** ayrıcalık istemiyor; seccomp filtresi her
  zaman ayrı bir çocuk süreçte kuruluyor, çünkü kurulum geri alınamaz ve
  test koşucusunu da kısıtlardı.
* **Uçtan uca testler** kullanıcı ad alanı ve gerçek bir ffmpeg istiyor.
  İkisi de yoksa atlanıyorlar - CI koşucusunda ffmpeg kurulu değil ve
  sandbox'ı sınamayan yeşil bir testten, dürüst bir "atlandı" daha iyi.

ffmpeg yolu ``FFMPEG_PATH`` ile verilebiliyor.
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import unittest

from sandbox import ffmpeg_sandbox as fs
from sandbox import seccomp


def _find_ffmpeg():
    return os.environ.get("FFMPEG_PATH") or shutil.which("ffmpeg")


FFMPEG = _find_ffmpeg()
NAMESPACES_OK = fs._probe_user_namespace() is None
SECCOMP_OK = fs._probe_seccomp() is None
X86_64 = os.uname().machine == "x86_64"

requires_sandbox = unittest.skipUnless(
    FFMPEG and NAMESPACES_OK and SECCOMP_OK and X86_64,
    "ffmpeg, kullanıcı ad alanı, seccomp ve x86_64 gerekiyor",
)
requires_seccomp = unittest.skipUnless(
    SECCOMP_OK and X86_64, "seccomp ve x86_64 gerekiyor"
)


def _run_confined(work, program):
    """``work``'ü filtre kurulmuş bir çocuk süreçte çalıştırır.

    Dönüş: ``("signal", isim)`` ya da ``("exit", kod)``. İstisna çıkarsa
    çıkış kodu 42 - bu, "syscall EPERM döndü" ile "süreç öldürüldü" arasını
    ayırmamızı sağlıyor.
    """
    pid = os.fork()
    if pid == 0:
        try:
            seccomp.set_no_new_privs()
            seccomp.install(program)
            work()
        except BaseException:
            os._exit(42)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return ("signal", signal.Signals(os.WTERMSIG(status)).name)
    return ("exit", os.WEXITSTATUS(status))


class BpfAssemblerTests(unittest.TestCase):
    def test_program_is_well_formed(self):
        program = seccomp.build_filter(seccomp.FFMPEG_SYSCALLS)
        self.assertGreater(len(program), 0)
        self.assertEqual(len(program) % 8, 0, "her BPF komutu 8 bayt olmalı")

    def test_unknown_syscall_name_is_rejected(self):
        with self.assertRaises(seccomp.SeccompError):
            seccomp.build_filter(["read", "boyle_bir_syscall_yok"])

    def test_undefined_label_is_rejected(self):
        asm = seccomp._Assembler()
        asm.jeq(1, jt="olmayan_etiket")
        with self.assertRaises(seccomp.SeccompError):
            asm.assemble()

    def test_backward_jump_is_rejected(self):
        # BPF ileri atlamaya izin veriyor, geriye atlamaya vermiyor; sessizce
        # sarmalanan bir uzaklık yanlış bir filtre üretirdi.
        asm = seccomp._Assembler()
        asm.label("bas")
        asm.jeq(1, jt="bas")
        with self.assertRaises(seccomp.SeccompError):
            asm.assemble()

    def test_oversized_jump_is_rejected(self):
        asm = seccomp._Assembler()
        asm.jeq(1, jt="uzak")
        for _ in range(300):
            asm.ret(seccomp.RET_ALLOW)
        asm.label("uzak")
        asm.ret(seccomp.RET_ALLOW)
        with self.assertRaises(seccomp.SeccompError):
            asm.assemble()


@requires_seccomp
class SeccompEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.program = seccomp.build_filter(seccomp.FFMPEG_SYSCALLS)

    def test_allowed_syscall_runs(self):
        self.assertEqual(_run_confined(lambda: os.write(1, b""), self.program),
                         ("exit", 0))

    def test_socket_is_killed(self):
        # Ağ syscall'ları izin listesinde yok: süreç SIGSYS ile ölüyor.
        kind, detail = _run_confined(socket.socket, self.program)
        self.assertEqual((kind, detail), ("signal", "SIGSYS"))

    def test_ptrace_is_killed(self):
        def work():
            import ctypes
            ctypes.CDLL("libc.so.6").ptrace(0, 0, 0, 0)

        self.assertEqual(_run_confined(work, self.program)[0], "signal")

    def test_mount_is_killed(self):
        def work():
            import ctypes
            ctypes.CDLL("libc.so.6").mount(b"x", b"/mnt", b"tmpfs", 0, None)

        self.assertEqual(_run_confined(work, self.program)[0], "signal")

    def test_fork_is_refused_without_killing(self):
        # clone CLONE_THREAD olmadan EPERM alıyor, öldürülmüyor: ffmpeg'in
        # kendi iş parçacığı açması yanlışlıkla ölümcül olmasın diye.
        self.assertEqual(_run_confined(os.fork, self.program), ("exit", 42))

    def test_thread_creation_still_works(self):
        # Bu test clone3 -> ENOSYS düşürmesini koruyor. O olmadan glibc
        # clone3 çağırıyor ve iş parçacığı açan her süreç SIGSYS alıyor.
        def work():
            done = []
            thread = threading.Thread(target=lambda: done.append(1))
            thread.start()
            thread.join()
            if not done:
                raise RuntimeError("iş parçacığı çalışmadı")

        self.assertEqual(_run_confined(work, self.program), ("exit", 0))


class ArgumentBuildingTests(unittest.TestCase):
    def setUp(self):
        self.policy = fs.Policy(ffmpeg_path="/usr/bin/ffmpeg")

    def test_protocol_whitelist_is_file_only(self):
        argv = fs._build_argv(self.policy, "web-720p", "mp4", "output.mp4")
        self.assertIn("-protocol_whitelist", argv)
        self.assertEqual(argv[argv.index("-protocol_whitelist") + 1], "file")

    def test_demuxer_is_pinned(self):
        argv = fs._build_argv(self.policy, "web-720p", "matroska,webm", "o.webm")
        self.assertEqual(argv[argv.index("-f") + 1], "matroska,webm")

    def test_stdin_is_closed_and_alloc_capped(self):
        argv = fs._build_argv(self.policy, "web-720p", "mp4", "o.mp4")
        self.assertIn("-nostdin", argv)
        self.assertIn("-max_alloc", argv)

    def test_input_path_is_fixed(self):
        # Girdinin özgün adı saldırgan kontrolünde; sandbox içinde sabit bir
        # ada bağlanıyor.
        argv = fs._build_argv(self.policy, "web-720p", "mp4", "o.mp4")
        self.assertEqual(argv[argv.index("-i") + 1], fs._IN_PATH)


class PolicyValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.source = os.path.join(self.tmp, "girdi.mp4")
        with open(self.source, "wb") as handle:
            handle.write(b"\x00" * 32)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(fs.SandboxError):
            fs.transcode(self.source, os.path.join(self.tmp, "o.mp4"),
                         profile="olmayan-profil")

    def test_unsupported_extension_is_rejected(self):
        weird = os.path.join(self.tmp, "girdi.exe")
        shutil.copy(self.source, weird)
        policy = fs.Policy(ffmpeg_path=FFMPEG or "/usr/bin/ffmpeg")
        with self.assertRaises(fs.SandboxError):
            fs.transcode(weird, os.path.join(self.tmp, "o.mp4"), policy=policy)

    def test_profile_and_output_container_must_match(self):
        # web-720p h264/aac üretiyor; .webm'e muxlamak ffmpeg'in içinden
        # anlaşılması zor bir hata olarak gelirdi.
        policy = fs.Policy(ffmpeg_path=FFMPEG or "/usr/bin/ffmpeg")
        with self.assertRaises(fs.SandboxError) as caught:
            fs.transcode(self.source, os.path.join(self.tmp, "o.webm"),
                         policy=policy)
        self.assertIn("web-720p", str(caught.exception))

    def test_missing_ffmpeg_fails_closed(self):
        policy = fs.Policy(ffmpeg_path=os.path.join(self.tmp, "yok"))
        with self.assertRaises(fs.SandboxError):
            fs.transcode(self.source, os.path.join(self.tmp, "o.mp4"), policy=policy)

    @unittest.skipIf(fs.apparmor_enabled(), "AppArmor bu makinede etkin")
    def test_apparmor_request_without_apparmor_fails_closed(self):
        # Yazma başarılı dönse bile profil uygulanmıyorsa çalıştırmıyoruz:
        # AppArmor'suz çekirdekte /proc/self/attr/exec duruyor ve yazma
        # sessizce başarılı oluyor.
        policy = fs.Policy(
            ffmpeg_path=FFMPEG or "/usr/bin/ffmpeg",
            apparmor_profile="minitube-ffmpeg",
        )
        target = os.path.join(self.tmp, "o.mp4")
        with self.assertRaises(fs.SandboxError):
            fs.transcode(self.source, target, policy=policy)
        self.assertFalse(os.path.exists(target), "çıktı üretilmemeliydi")


@requires_sandbox
class SandboxEndToEndTests(unittest.TestCase):
    """Gerçek ffmpeg, gerçek ad alanları."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sandbox-test-")
        cls.source = os.path.join(cls.tmp, "girdi.mp4")
        subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
             "-f", "lavfi", "-i", "testsrc=duration=1:size=160x120:rate=10",
             "-c:v", "libx264", "-preset", "ultrafast", cls.source],
            check=True, capture_output=True, timeout=120,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.policy = fs.Policy(ffmpeg_path=FFMPEG)

    def _raw_run(self, argv, **overrides):
        """Genel API'yi atlayıp ad alanı katmanını tek başına sınar."""
        out_dir = tempfile.mkdtemp(dir=self.tmp)
        spec = {
            "ffmpeg": FFMPEG,
            "input": self.source,
            "out_dir": out_dir,
            "argv": [fs._FFMPEG_PATH] + argv,
            "limits": {
                "memory_bytes": self.policy.memory_bytes,
                "cpu_seconds": self.policy.cpu_seconds,
                "max_output_bytes": self.policy.max_output_bytes,
                "max_open_files": self.policy.max_open_files,
            },
            "tmpfs_bytes": self.policy.tmpfs_bytes,
            "apparmor_profile": None,
            "syscalls": self.policy.syscalls,
        }
        spec.update(overrides)
        return fs._run_stage2(spec, self.policy)

    def _listener(self):
        """127.0.0.1'de kayıt tutan bir dinleyici açar, vuruş listesini döner."""
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        self.addCleanup(server.close)
        hits = []

        def accept_loop():
            while True:
                try:
                    connection, _ = server.accept()
                except OSError:
                    return
                hits.append(1)
                connection.close()

        threading.Thread(target=accept_loop, daemon=True).start()
        return server.getsockname()[1], hits

    def test_transcode_produces_playable_output(self):
        target = os.path.join(self.tmp, "cikti.mp4")
        result = fs.transcode(self.source, target, policy=self.policy)
        self.assertTrue(os.path.isfile(target))
        self.assertGreater(result.output_bytes, 0)
        probe = subprocess.run(
            [FFMPEG, "-hide_banner", "-i", target],
            capture_output=True, timeout=60,
        )
        self.assertIn(b"Video:", probe.stderr)

    def test_thumbnail_profile_produces_an_image(self):
        target = os.path.join(self.tmp, "kapak.png")
        result = fs.transcode(self.source, target, profile="thumbnail",
                              policy=self.policy)
        self.assertGreater(result.output_bytes, 0)
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(8), b"\x89PNG\r\n\x1a\n")

    def test_network_is_unreachable(self):
        # Yerel bir dinleyici: internet gerekmiyor, test hermetik.
        port, hits = self._listener()
        url = f"http://127.0.0.1:{port}/x.mp4"
        argv = ["-nostdin", "-hide_banner", "-loglevel", "error",
                "-protocol_whitelist", "file,http,tcp", "-i", url, "-f", "null", "-"]

        # Önce sandbox'sız: saldırının gerçekten çalıştığını doğrula, yoksa
        # test hiçbir şey kanıtlamaz.
        subprocess.run([FFMPEG] + argv, capture_output=True, timeout=60)
        self.assertEqual(len(hits), 1, "temel çizgi kurulamadı")
        hits.clear()

        self._raw_run(argv)
        self.assertEqual(hits, [], "sandbox içinden ağa çıkıldı")

    def test_network_namespace_blocks_on_its_own(self):
        # Yukarıdaki test iki katmanın *birleşimini* ölçüyor: seccomp ffmpeg'i
        # socket() çağrısında zaten öldürüyor, dolayısıyla ağ ad alanı
        # kaldırılsa bile test geçiyordu (mutasyonla görüldü). Burada seccomp
        # bilerek gevşetiliyor: soket açmak serbest, yine de bağlanılamamalı.
        port, hits = self._listener()
        url = f"http://127.0.0.1:{port}/x.mp4"
        argv = ["-nostdin", "-hide_banner", "-loglevel", "error",
                "-protocol_whitelist", "file,http,tcp", "-i", url, "-f", "null", "-"]

        subprocess.run([FFMPEG] + argv, capture_output=True, timeout=60)
        self.assertEqual(len(hits), 1, "temel çizgi kurulamadı")
        hits.clear()

        relaxed = list(seccomp.FFMPEG_SYSCALLS) + list(seccomp.NETWORK_SYSCALLS)
        done = self._raw_run(argv, syscalls=relaxed)
        self.assertEqual(hits, [], "ağ ad alanı tek başına engellemiyor")
        # SIGSYS ile değil, ağ hatasıyla başarısız olmalı: engelleyen katmanın
        # seccomp değil ad alanı olduğunu böyle ayırt ediyoruz.
        self.assertNotEqual(done.returncode, -31, "seccomp öldürdü, ad alanı değil")

    def test_host_filesystem_is_invisible(self):
        done = self._raw_run(
            ["-nostdin", "-hide_banner", "-loglevel", "error",
             "-protocol_whitelist", "file", "-i", "/etc/passwd", "-f", "null", "-"]
        )
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"No such file", done.stderr)

    def test_writing_outside_the_output_directory_fails(self):
        done = self._raw_run(
            ["-nostdin", "-hide_banner", "-loglevel", "error",
             "-protocol_whitelist", "file", "-f", "mp4", "-i", fs._IN_PATH,
             "-c", "copy", "-y", "/kacis.mp4"]
        )
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"Read-only file system", done.stderr)
        self.assertFalse(os.path.exists("/kacis.mp4"))

    def test_disguised_container_is_rejected(self):
        # .mp4 uzantılı ama aslında bir concat betiği. Demuxer sabitlendiği
        # için ffmpeg onu concat olarak açmaya hiç kalkışmıyor.
        disguised = os.path.join(self.tmp, "kotu.mp4")
        with open(disguised, "w") as handle:
            handle.write("ffconcat version 1.0\nfile /etc/passwd\n")
        with self.assertRaises(fs.TranscodeError):
            fs.transcode(disguised, os.path.join(self.tmp, "kotu-out.mp4"),
                         policy=self.policy)

    def test_wall_clock_timeout_kills_the_job(self):
        policy = fs.Policy(ffmpeg_path=FFMPEG, wall_clock_seconds=3)
        spec_argv = ["-nostdin", "-hide_banner", "-loglevel", "error",
                     "-protocol_whitelist", "file", "-stream_loop", "2000",
                     "-f", "mp4", "-i", fs._IN_PATH,
                     "-c:v", "libx264", "-preset", "placebo", "-y", "/out/o.mp4"]
        out_dir = tempfile.mkdtemp(dir=self.tmp)
        spec = {
            "ffmpeg": FFMPEG, "input": self.source, "out_dir": out_dir,
            "argv": [fs._FFMPEG_PATH] + spec_argv,
            "limits": {
                "memory_bytes": policy.memory_bytes,
                "cpu_seconds": policy.cpu_seconds,
                "max_output_bytes": policy.max_output_bytes,
                "max_open_files": policy.max_open_files,
            },
            "tmpfs_bytes": policy.tmpfs_bytes, "apparmor_profile": None,
        }
        with self.assertRaises(fs.TranscodeError):
            fs._run_stage2(spec, policy)

    def test_no_mounts_leak_to_the_host(self):
        fs.transcode(self.source, os.path.join(self.tmp, "sizinti.mp4"),
                     policy=self.policy)
        with open("/proc/self/mountinfo") as handle:
            self.assertNotIn("mtsandbox", handle.read())


if __name__ == "__main__":
    unittest.main()
