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
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import uuid

from sandbox import ffmpeg_sandbox as fs
from sandbox import minisandbox as ms
from sandbox import seccomp


def _find_ffmpeg():
    return os.environ.get("FFMPEG_PATH") or shutil.which("ffmpeg")


FFMPEG = _find_ffmpeg()
NAMESPACES_OK = ms.probe_user_namespace() is None
SECCOMP_OK = ms.probe_seccomp() is None
X86_64 = os.uname().machine == "x86_64"

requires_sandbox = unittest.skipUnless(
    FFMPEG and NAMESPACES_OK and SECCOMP_OK and X86_64,
    "ffmpeg, kullanıcı ad alanı, seccomp ve x86_64 gerekiyor",
)
requires_seccomp = unittest.skipUnless(
    SECCOMP_OK and X86_64, "seccomp ve x86_64 gerekiyor"
)
# Motor testleri ffmpeg istemiyor: yük olarak sistemin kendi kabuğu
# kullanılıyor. CI koşucusunda gerçekten koşan kısım bu.
requires_engine = unittest.skipUnless(
    NAMESPACES_OK and SECCOMP_OK and X86_64,
    "kullanıcı ad alanı, seccomp ve x86_64 gerekiyor",
)


_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _run_confined(body, allowed=None):
    """``body``'yi filtre kurulmuş **ayrı bir süreçte** çalıştırır.

    Dönüş: ``("signal", isim)`` ya da ``("exit", kod)``. İstisna çıkarsa
    çıkış kodu 42 - bu, "syscall EPERM döndü" ile "süreç öldürüldü" arasını
    ayırmamızı sağlıyor.

    Fork yerine alt süreç kullanılıyor: ağ testleri kabul döngüsü için iş
    parçacığı açıyor ve çok iş parçacıklı bir süreçte fork etmek, çocukta
    başka bir iş parçacığının tuttuğu kilitlerle kilitlenme riski taşıyor
    (Python 3.12 bunu uyarı olarak da söylüyor).
    """
    code = (
        "import sys\n"
        f"sys.path.insert(0, {_REPO_ROOT!r})\n"
        "from sandbox import seccomp\n"
        f"seccomp.apply_ffmpeg_policy({allowed!r})\n"
        "try:\n"
        + textwrap.indent(textwrap.dedent(body), "    ")
        + "\nexcept BaseException:\n"
        "    raise SystemExit(42)\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=60
    )
    if done.returncode < 0:
        return ("signal", signal.Signals(-done.returncode).name)
    return ("exit", done.returncode)


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
    def test_allowed_syscall_runs(self):
        self.assertEqual(_run_confined("import os; os.write(1, b'')"),
                         ("exit", 0))

    def test_socket_is_killed(self):
        # Ağ syscall'ları izin listesinde yok: süreç SIGSYS ile ölüyor.
        self.assertEqual(_run_confined("import socket; socket.socket()"),
                         ("signal", "SIGSYS"))

    def test_ptrace_is_killed(self):
        self.assertEqual(
            _run_confined("import ctypes\n"
                          "ctypes.CDLL('libc.so.6').ptrace(0, 0, 0, 0)")[0],
            "signal",
        )

    def test_mount_is_killed(self):
        self.assertEqual(
            _run_confined("import ctypes\n"
                          "ctypes.CDLL('libc.so.6')"
                          ".mount(b'x', b'/mnt', b'tmpfs', 0, None)")[0],
            "signal",
        )

    def test_fork_is_refused_without_killing(self):
        # fork ve clone ikisi de EPERM dönüyor, öldürmüyor: ffmpeg'in kendi
        # iş parçacığı açması yanlışlıkla ölümcül olmasın diye, ve aynı
        # niyetin libc'nin seçimine göre farklı sonuçlanmaması için.
        self.assertEqual(_run_confined("import os; os.fork()"), ("exit", 42))

    def test_thread_creation_still_works(self):
        # Bu test clone3 -> ENOSYS düşürmesini koruyor. O olmadan glibc
        # clone3 çağırıyor ve iş parçacığı açan her süreç SIGSYS alıyor.
        self.assertEqual(
            _run_confined(
                "import threading\n"
                "done = []\n"
                "t = threading.Thread(target=lambda: done.append(1))\n"
                "t.start(); t.join()\n"
                "assert done, 'iş parçacığı çalışmadı'\n"
            ),
            ("exit", 0),
        )


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

    @unittest.skipIf(ms.apparmor_enabled(), "AppArmor bu makinede etkin")
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


@requires_engine
class EngineTests(unittest.TestCase):
    """Motorun kendisi - ffmpeg gerekmiyor.

    Yük olarak sistemin kendi kabuğu kullanılıyor; tek ihtiyacı libc ve ELF
    yükleyicisi, ikisi de her Linux'ta var. CI koşucusunda gerçekten koşan
    kısım bu: ffmpeg'e bağlı testler orada atlanıyor, bunlar atlanmıyor.
    """

    @classmethod
    def setUpClass(cls):
        shell = shutil.which("sh")
        if shell is None:
            raise unittest.SkipTest("kabuk bulunamadı")
        cls.shell = os.path.realpath(shell)
        cls.libraries = ms.shared_libraries(cls.shell)
        # Kabuğun syscall kümesi strace ile ölçüldü: ffmpeg'inkiyle
        # neredeyse aynı, farkı yalnızca süreç grubu sorguları.
        cls.syscalls = list(seccomp.FFMPEG_SYSCALLS) + ["getppid", "getpgrp"]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="engine-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _sh(self, script, **kwargs):
        kwargs.setdefault("syscalls", self.syscalls)
        kwargs.setdefault("timeout", 60)
        ro_binds = [self.shell] + self.libraries + list(kwargs.pop("ro_binds", []))
        return ms.run([self.shell, "-c", script], ro_binds=ro_binds, **kwargs)

    def test_command_runs_and_stdout_comes_back(self):
        done = self._sh("echo merhaba")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), b"merhaba")

    def test_root_is_read_only(self):
        done = self._sh("echo x > /kacis")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"Read-only file system", done.stderr)
        self.assertFalse(os.path.exists("/kacis"))

    def test_host_filesystem_is_invisible(self):
        done = self._sh(
            "if [ -r /etc/passwd ]; then echo GORUNUYOR; else echo yok; fi"
        )
        self.assertEqual(done.stdout.strip(), b"yok")

    def test_proc_is_not_mounted(self):
        done = self._sh("if [ -d /proc/1 ]; then echo VAR; else echo yok; fi")
        self.assertEqual(done.stdout.strip(), b"yok")

    def test_writable_bind_works_and_stays_inside(self):
        out_dir = os.path.join(self.tmp, "out")
        os.mkdir(out_dir)
        done = self._sh("echo veri > /out/dosya", rw_binds=[(out_dir, "/out")])
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(os.path.join(out_dir, "dosya")) as handle:
            self.assertEqual(handle.read().strip(), "veri")

    def test_dev_null_is_a_working_character_device(self):
        # Demoda bulunan hata: /dev olmadan "2>/dev/null" gibi çok yaygın bir
        # deyim kırılıyor ve suç sandbox'a yıkılıyor.
        #
        # Yalnızca "komut yine de tamamlandı" demek yetmiyor: /dev hiç
        # yokken de tamamlanıyor, sadece stderr'e hata düşüyor. O yüzden
        # aygıt olduğunu ve yönlendirmenin sessiz kaldığını sınıyoruz.
        done = self._sh("if [ -c /dev/null ]; then echo AYGIT; else echo yok; fi")
        self.assertEqual(done.stdout.strip(), b"AYGIT")
        quiet = self._sh("echo gurultu 2>/dev/null")
        self.assertEqual(quiet.returncode, 0, quiet.stderr)
        self.assertEqual(quiet.stderr, b"", "yönlendirme sessiz kalmalıydı")

    def test_writable_bind_is_not_executable(self):
        # Saldırgan yazabildiği tek yere bir yük bırakırsa çalıştıramamalı.
        # Yükü ana makineden koyuyoruz: içeride kopyalamak harici komut,
        # o da fork gerektirir ve fork zaten yasak.
        out_dir = os.path.join(self.tmp, "out")
        os.mkdir(out_dir)
        planted = os.path.join(out_dir, "yuk")
        shutil.copy(self.shell, planted)
        os.chmod(planted, 0o755)
        # "exec" fork etmiyor, süreci yerine koyuyor - yani bu deneme
        # seccomp'un fork yasağına takılmadan noexec'i sınıyor.
        done = self._sh("exec /out/yuk -c 'echo CALISTI'",
                        rw_binds=[(out_dir, "/out")])
        self.assertNotIn(b"CALISTI", done.stdout)
        self.assertIn(b"denied", done.stderr.lower())

    def test_process_id_namespace_is_separate(self):
        # Yeni PID ad alanında ilk süreç 1 numara. Ana makinenin PID'lerini
        # görüyor olsaydı burası büyük bir sayı olurdu.
        done = self._sh("echo $$")
        self.assertEqual(done.stdout.strip(), b"1")

    def test_helper_process_cannot_be_spawned(self):
        # fork ve clone ikisi de reddediliyor, ikisi de EPERM - öldürme yok,
        # yani kabuk hatayı bildirebiliyor.
        done = self._sh("/bin/true; echo CALISTI")
        self.assertNotIn(b"CALISTI", done.stdout)
        self.assertIn(b"ork", done.stderr)  # "Cannot fork"

    def test_network_namespace_is_empty(self):
        # seccomp bilerek gevşetiliyor: soket açmak serbest, yine de
        # bağlanılamamalı. Katmanı tek başına ölçen test bu.
        #
        # Yük bash: /dev/tcp yönlendirmesi bash'e özgü ve fazladan bir ikili
        # (netcat, curl) gerektirmeden soket açmanın tek yolu. dash'te yok.
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash bulunamadı (/dev/tcp gerekiyor)")
        bash = os.path.realpath(bash)
        bash_libraries = ms.shared_libraries(bash)

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        self.addCleanup(server.close)
        port = server.getsockname()[1]
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
        script = f"exec 3<>/dev/tcp/127.0.0.1/{port} && echo ACIK || echo kapali"

        # Temel çizgi: aynı betik sandbox dışında bağlanabiliyor mu? Bu
        # olmadan test hiçbir şey kanıtlamaz - sadece bash'in beceriksiz
        # olduğunu gösterirdi.
        baseline = subprocess.run([bash, "-c", script],
                                  capture_output=True, timeout=30)
        self.assertIn(b"ACIK", baseline.stdout, "temel çizgi kurulamadı")
        self.assertEqual(len(hits), 1)
        hits.clear()

        relaxed = self.syscalls + list(seccomp.NETWORK_SYSCALLS)
        done = ms.run([bash, "-c", script],
                      ro_binds=[bash] + bash_libraries,
                      syscalls=relaxed, timeout=60)
        self.assertEqual(hits, [], "sandbox içinden ağa çıkıldı")
        self.assertNotIn(b"ACIK", done.stdout)

    def test_timeout_kills_the_command(self):
        with self.assertRaises(ms.SandboxTimeout):
            # Meşgul döngü: fork gerektirmiyor, kendiliğinden de bitmiyor.
            self._sh("while : ; do : ; done", timeout=2)

    def test_timeout_leaves_no_surviving_process(self):
        """Zaman aşımı gerçekten öldürmeli, yalnızca beklemeyi bırakmamalı.

        Bu bir regresyon testi: önceki sürüm zaman aşımında yalnızca
        ``unshare``'i öldürüyordu ve yük hayatta kalıp CPU yakmaya devam
        ediyordu (ana makinede PID 1'e evlat edinilmiş hâlde ölçüldü).

        Belirteç çalışma anında üretiliyor. Sabit bir dize kullanmak
        yanıltıcı olurdu: aynı dize testi başlatan kabuğun komut satırında da
        geçer ve kendi harness'ımızı sızıntı sanardık - bir kez öyle oldu.
        """
        marker = "sandbox-test-" + uuid.uuid4().hex

        def survivors():
            found = []
            mine = {str(os.getpid()), str(os.getppid())}
            for entry in os.listdir("/proc"):
                if not entry.isdigit() or entry in mine:
                    continue
                try:
                    with open(f"/proc/{entry}/cmdline", "rb") as handle:
                        if marker.encode() in handle.read():
                            found.append(entry)
                except OSError:
                    pass
            return found

        self.assertEqual(survivors(), [], "belirteç zaten kullanımda")
        with self.assertRaises(ms.SandboxTimeout):
            self._sh(f": {marker}; while : ; do : ; done", timeout=2)
        # Öldürme eşzamansız; çekirdeğin süreci kaldırmasına biraz süre ver.
        for _ in range(20):
            if not survivors():
                break
            time.sleep(0.1)
        self.assertEqual(survivors(), [], "yük zaman aşımından sağ çıktı")

    def test_no_mounts_leak_to_the_host(self):
        self._sh("echo x")
        with open("/proc/self/mountinfo") as handle:
            self.assertNotIn("minisandbox", handle.read())

    def test_capabilities_are_probed_without_confining_the_caller(self):
        # Yetenek denemesi filtreyi çocuk süreçte kuruyor; test koşucusunun
        # kendisi kısıtlanmış olsaydı sonraki testler ölürdü.
        self.assertIsNone(ms.probe_seccomp())
        self.assertEqual(socket.socket().close(), None)

    def test_relative_bind_target_is_rejected(self):
        with self.assertRaises(ms.SandboxError):
            ms.run([self.shell, "-c", "true"],
                   ro_binds=[(self.shell, "goreli/yol")])


class AppArmorProfileTests(unittest.TestCase):
    """AppArmor katmanı - bu katman yalnızca AppArmor'lu bir çekirdekte sınanır.

    Depoda geliştirme yapılan makinede AppArmor yok; CI koşucusunda var.
    O yüzden bu testler orada koşuyor ve `MINITUBE_APPARMOR_SELFTEST`
    işaretine bakıyorlar: profiller yüklenemediyse atlıyorlar, sessizce
    "geçti" demiyorlar.
    """

    PROFILE_DIR = os.path.join(_REPO_ROOT, "sandbox", "apparmor")
    SELFTEST_READY = os.environ.get("MINITUBE_APPARMOR_SELFTEST") == "1"

    @unittest.skipUnless(shutil.which("apparmor_parser"), "apparmor_parser yok")
    def test_real_profile_parses(self):
        # Sözdizimi denetimi çekirdeğe yükleme gerektirmiyor, yani AppArmor
        # etkin olmayan bir makinede bile anlamlı.
        done = subprocess.run(
            [shutil.which("apparmor_parser"), "-Q",
             os.path.join(self.PROFILE_DIR, "minitube-ffmpeg")],
            capture_output=True, timeout=60,
        )
        self.assertEqual(done.returncode, 0,
                         done.stderr.decode("utf-8", "replace"))

    @requires_engine
    @unittest.skipUnless(SELFTEST_READY, "öz sınama profilleri yüklü değil")
    def test_profile_is_actually_enforced(self):
        """Aynı komut, iki profil, iki sonuç.

        "Profil yüklendi" ile "profil iş görüyor" aynı şey değil, ve geçiş
        isteğinin kabul edilmesi de kanıt değil - AppArmor'suz bir çekirdekte
        o yazma sessizce başarılı oluyor. Tek sağlam kanıt fark: izin veren
        profille komut çalışmalı, hiçbir kuralı olmayan profille
        çalışmamalı. İkisi aynı çıkarsa AppArmor uygulanmıyor demektir.
        """
        shell = os.path.realpath(shutil.which("sh"))
        libraries = ms.shared_libraries(shell)
        syscalls = list(seccomp.FFMPEG_SYSCALLS) + ["getppid", "getpgrp"]

        def run_under(profile):
            return ms.run(
                [shell, "-c", "echo merhaba"],
                ro_binds=[shell] + libraries,
                syscalls=syscalls,
                apparmor_profile=profile,
                timeout=60,
            )

        allowed = run_under("minitube-sandbox-selftest-allow")
        self.assertEqual(allowed.returncode, 0,
                         allowed.stderr.decode("utf-8", "replace"))
        self.assertIn(b"merhaba", allowed.stdout)

        denied = run_under("minitube-sandbox-selftest-deny")
        self.assertNotEqual(denied.returncode, 0,
                            "boş profille komut çalıştı: AppArmor uygulanmıyor")
        self.assertNotIn(b"merhaba", denied.stdout)

    @requires_engine
    @unittest.skipUnless(ms.apparmor_enabled(), "AppArmor etkin değil")
    def test_unknown_profile_fails_closed(self):
        # Yüklü olmayan bir profil istendiğinde iş çalışmamalı. Geçiş isteği
        # yazılabiliyor ama exec reddediliyor; sessizce profilsiz çalışmak
        # en kötü sonuç olurdu.
        shell = os.path.realpath(shutil.which("sh"))
        done = ms.run(
            [shell, "-c", "echo merhaba"],
            ro_binds=[shell] + ms.shared_libraries(shell),
            syscalls=list(seccomp.FFMPEG_SYSCALLS) + ["getppid", "getpgrp"],
            apparmor_profile="minitube-boyle-bir-profil-yok",
            timeout=60,
        )
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"merhaba", done.stdout)


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

    def _raw_run(self, argv, syscalls=None):
        """Genel API'yi atlayıp sandbox katmanlarını tek başına sınar.

        ``transcode()`` argümanları kendisi üretiyor; burada verilen argv
        doğrudan çalıştırılıyor, böylece 2. katmanı (protokol kısıtı)
        atlayıp alttaki katmanların tek başına ne yaptığı görülebiliyor.
        """
        out_dir = tempfile.mkdtemp(dir=self.tmp)
        policy = fs.Policy(ffmpeg_path=FFMPEG, syscalls=syscalls)
        return fs.run_ffmpeg([fs._FFMPEG_PATH] + argv, self.source, out_dir,
                             policy)

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
        argv = [fs._FFMPEG_PATH, "-nostdin", "-hide_banner", "-loglevel", "error",
                "-protocol_whitelist", "file", "-stream_loop", "2000",
                "-f", "mp4", "-i", fs._IN_PATH,
                "-c:v", "libx264", "-preset", "placebo", "-y", "/out/o.mp4"]
        out_dir = tempfile.mkdtemp(dir=self.tmp)
        with self.assertRaises(fs.TranscodeError):
            fs.run_ffmpeg(argv, self.source, out_dir, policy)

    def test_no_mounts_leak_to_the_host(self):
        fs.transcode(self.source, os.path.join(self.tmp, "sizinti.mp4"),
                     policy=self.policy)
        with open("/proc/self/mountinfo") as handle:
            self.assertNotIn("mtsandbox", handle.read())


if __name__ == "__main__":
    unittest.main()
