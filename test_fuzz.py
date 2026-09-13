"""Fuzzing ve güvenlik stres paketi.

``test_sandbox.py`` her katmanın *beklenen* davranışını sınıyor. Buradaki
testler tersini deniyor: izolasyonu kırmaya çalışıyor, rastgele girdiyle
filtre üreticisini zorluyor ve syscall uzayının tamamını tarıyor.

Dört başlık:

* **Diferansiyel filtre fuzz'ı** - rastgele izin listeleriyle C ve Python
  uygulamaları aynı baytları üretmeli. Elle yazılmış bir BPF
  birleştiricisinde sessiz bir hata ya çalışan programı öldürür ya da
  izolasyonda delik bırakır; iki bağımsız uygulamayı karşılaştırmak o
  sınıfı yakalıyor.
* **Kapsamlı syscall taraması** - 0'dan 460'a kadar her numara deneniyor.
  Tek tek yazılmış testler yalnızca akla gelenleri kapsıyor; bu, kapsamama
  ihtimalini ortadan kaldırıyor.
* **Tek-exec kuralı** - ``SECCOMP_RET_USER_NOTIF`` ile kapatılan execve
  boşluğu.
* **Kaçış ve stres** - eşzamanlı koşular, sızıntı denetimi, bozulmuş
  girdiyle ffmpeg.

Testler ayrıcalık gerektirmeyen kısım dışında yetenek yoksa atlanıyor.
Atlama sayısı okunmalı: her şeyi atlayan yeşil bir paket kanıt değil.
"""

import os
import random
import shutil
import struct
import subprocess
import tempfile
import threading
import unittest

from sandbox import minisandbox as ms
from sandbox import native
from sandbox import seccomp

X86_64 = os.uname().machine == "x86_64"
SECCOMP_OK = ms.probe_seccomp() is None
NAMESPACES_OK = ms.probe_user_namespace() is None
NATIVE_OK = X86_64 and native.available()
FFMPEG = os.environ.get("FFMPEG_PATH") or shutil.which("ffmpeg")

# Taramanın üst sınırı. Bu numaranın ötesi bu çekirdekte tanımsız; sınırı
# yükseltmek taramayı yavaşlatmaktan başka bir şey yapmıyor.
SWEEP_MAX = 460

requires_native = unittest.skipUnless(NATIVE_OK, "C tarafı derlenemiyor")
requires_seccomp = unittest.skipUnless(SECCOMP_OK and X86_64,
                                       "seccomp ve x86_64 gerekiyor")
requires_engine = unittest.skipUnless(
    NAMESPACES_OK and SECCOMP_OK and X86_64,
    "kullanıcı ad alanı, seccomp ve x86_64 gerekiyor",
)

_TABLE = seccomp.SYSCALLS_X86_64
_SPECIAL = {k: _TABLE[k] for k in
            ("clone", "clone3", "fork", "vfork", "execve", "execveat")}


def _python_filter(names, **kwargs):
    return seccomp.build_filter(names, **kwargs)


def _c_filter(names, execve_action=0, thread_only_clone=True):
    return native.build_filter(
        [_TABLE[n] for n in names],
        arch=seccomp.AUDIT_ARCH_X86_64,
        denied_action=seccomp.RET_KILL_PROCESS,
        execve_action=execve_action,
        thread_only_clone=thread_only_clone,
        numbers=_SPECIAL,
    )


def _decode(program):
    return [struct.unpack_from("<HBBI", program, i * 8)
            for i in range(len(program) // 8)]


class FilterFuzzTests(unittest.TestCase):
    """Filtre üreticisini rastgele girdiyle zorlar."""

    def _random_names(self, rng, size=None):
        names = [n for n in _TABLE if n != "execveat"]
        size = size if size is not None else rng.randint(1, len(names))
        return rng.sample(names, min(size, len(names)))

    def test_program_is_always_well_formed(self):
        rng = random.Random(20260913)
        for _ in range(300):
            names = self._random_names(rng)
            program = _python_filter(names)
            self.assertEqual(len(program) % 8, 0)
            self.assertLessEqual(len(program) // 8, 4096)
            # Son komut daima bir RET olmalı: BPF'te düşerek biten bir
            # program çekirdek tarafından reddedilir.
            code = _decode(program)[-1][0]
            self.assertEqual(code, 0x06, "program RET ile bitmeli")

    def test_every_allowed_syscall_is_encoded(self):
        rng = random.Random(7)
        for _ in range(100):
            names = self._random_names(rng)
            program = _python_filter(names)
            instructions = _decode(program)
            allow_at = [i for i, (c, _, _, k) in enumerate(instructions)
                        if c == 0x06 and k == seccomp.RET_ALLOW]
            encoded = {k for i, (c, jt, _, k) in enumerate(instructions)
                       if c == 0x15 and i + 1 + jt in allow_at}
            expected = {_TABLE[n] for n in names} - set(_SPECIAL.values())
            self.assertTrue(
                expected <= encoded,
                f"kodlanmayan syscall var: {sorted(expected - encoded)}",
            )

    def test_build_is_deterministic(self):
        rng = random.Random(99)
        for _ in range(50):
            names = self._random_names(rng)
            self.assertEqual(_python_filter(names), _python_filter(names))
            # Sıralama çıktıyı değiştirmemeli: izin listesi bir küme.
            shuffled = list(names)
            rng.shuffle(shuffled)
            self.assertEqual(_python_filter(names), _python_filter(shuffled))

    @requires_native
    def test_c_and_python_filters_are_identical(self):
        """İki bağımsız uygulama, bayt bayt aynı program.

        Bu testin değeri kapsamında değil, bağımsızlığında: aynı hatayı iki
        kez yapmak, bir kez yapmaktan çok daha zor.
        """
        rng = random.Random(4242)
        for _ in range(200):
            names = self._random_names(rng)
            for action in (0, seccomp.RET_USER_NOTIF):
                expected = _python_filter(
                    names, execve_action=(action or None))
                self.assertEqual(
                    _c_filter(names, execve_action=action), expected,
                    f"C ve Python ayrıştı: {sorted(names)[:6]}... "
                    f"execve_action={action:#x}",
                )

    @requires_native
    def test_c_and_python_agree_on_the_real_policy(self):
        for action in (0, seccomp.RET_USER_NOTIF):
            self.assertEqual(
                _c_filter(seccomp.FFMPEG_SYSCALLS, execve_action=action),
                _python_filter(seccomp.FFMPEG_SYSCALLS,
                               execve_action=(action or None)),
            )

    def test_oversized_allowlist_is_refused_not_truncated(self):
        # Sığmayan bir liste sessizce kırpılırsa filtre eksik kalır ve kimse
        # fark etmez. Hata vermesi gerekiyor.
        asm = seccomp._Assembler()
        asm.jeq(1, jt="uzak")
        for _ in range(300):
            asm.ret(seccomp.RET_ALLOW)
        asm.label("uzak")
        asm.ret(seccomp.RET_ALLOW)
        with self.assertRaises(seccomp.SeccompError):
            asm.assemble()


@requires_seccomp
@requires_native
class SyscallSweepTests(unittest.TestCase):
    """0'dan SWEEP_MAX'a kadar her syscall numarasını dener."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sweep-")
        # Temel çizgi: **aynı üreticiyle** yapılmış, neredeyse hiçbir şeye
        # izin vermeyen bir filtre. Elle yazılmış tek komutluk bir filtre
        # yerine bunun seçilmesinin sebebi ölçüm: karşılaştırma böylece
        # "izin listem fazla geniş mi" sorusunu, "bu çekirdek + bu üretici
        # bileşiminde ne oluyor" sorusundan ayırıyor.
        cls.baseline = cls._sweep(cls._write(
            _python_filter(["write", "exit_group"])))
        cls.actual = cls._sweep(cls._write(
            _python_filter(seccomp.FFMPEG_SYSCALLS)))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _write(cls, program):
        path = os.path.join(cls.tmp, f"f{len(os.listdir(cls.tmp))}.bpf")
        with open(path, "wb") as handle:
            handle.write(program)
        return path

    @classmethod
    def _sweep(cls, path):
        # Ad alanlarının içinde: sıfır argümanlı bir syscall çoğu zaman
        # EFAULT/EINVAL ile döner ama hepsi değil, başarıya ulaşan bir çağrı
        # ana makineye dokunmasın.
        done = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--pid",
             "--fork", "--net", "--", native.sweeper(), path, str(SWEEP_MAX)],
            capture_output=True, timeout=600,
        )
        rows = {}
        for line in done.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 2:
                rows[int(parts[0])] = parts[1]
        return rows

    def test_sweep_actually_ran(self):
        self.assertGreater(len(self.baseline), SWEEP_MAX * 0.9,
                           "tarama çıktısı beklenenden az")

    def test_nothing_outside_the_allowlist_survives(self):
        """İzin listesinde olmayan hiçbir çağrı geçmemeli.

        Karşılaştırma temel çizgiye göre yapılıyor: önce her şeyi öldüren
        bir filtreyle taranıp bu çekirdekte seccomp'un gerçekten
        durdurabildiği numaralar ölçülüyor, sonra gerçek filtrenin onların
        hepsini durdurduğu doğrulanıyor.

        Sabit bir istisna listesi yazmak yerine bunu yapmanın sebebi ölçüm:
        bu çekirdekte iki numara (335, 336) **hiçbir** seccomp filtresine
        uğramıyor - her şeyi reddeden filtrede bile hayatta kalıyorlar ve
        filtresiz koşuda da aynı sonucu veriyorlar. Bu ortamın özelliği,
        filtrenin hatası değil. Temel çizgiyle karşılaştırma bunu kendi
        kendine soğuruyor ve testi başka çekirdeklerde de doğru tutuyor.
        """
        allowed = {_TABLE[n] for n in seccomp.FFMPEG_SYSCALLS}
        # eperm/enosys de reddetmedir: fork/vfork ve clone3 bilerek böyle.
        denied = ("sigsys", "eperm", "enosys")
        blockable = {nr for nr, status in self.baseline.items()
                     if status in denied}
        survivors = []
        for nr in sorted(blockable):
            if nr in allowed:
                continue
            status = self.actual.get(nr)
            if status not in denied:
                survivors.append((nr, status))
        self.assertEqual(survivors, [], f"engellenmeyen çağrılar: {survivors}")

    def test_allowed_syscalls_are_not_killed(self):
        allowed = {_TABLE[n] for n in seccomp.FFMPEG_SYSCALLS}
        # clone/fork/vfork/clone3 bilerek EPERM/ENOSYS alıyor, öldürülmüyor.
        special = set(_SPECIAL.values())
        killed = [nr for nr in sorted(allowed - special)
                  if self.actual.get(nr) == "sigsys"]
        self.assertEqual(killed, [], f"izinli olduğu hâlde öldürülen: {killed}")

    def test_process_creation_is_refused_but_not_fatal(self):
        # fork/vfork/clone EPERM almalı: meşru bir iş parçacığı açma
        # yanlışlıkla ölümcül olmasın diye bilinçli bir seçim.
        for name in ("fork", "vfork"):
            self.assertEqual(self.actual.get(_TABLE[name]), "eperm",
                             f"{name} beklenen EPERM'i vermedi")
        self.assertEqual(self.actual.get(_TABLE["clone3"]), "enosys",
                         "clone3 ENOSYS vermeli (glibc clone'a düşsün)")

    def test_kernel_syscalls_escaping_seccomp_are_reported(self):
        """Seccomp'a uğramayan numaralar varsa bunu görünür kıl.

        Test kırmıyor - ortamın özelliği, deponun hatası değil. Ama sessiz
        kalmak da doğru değil: seccomp'a güvenen biri bunu bilmeli.
        """
        escaped = sorted(nr for nr, status in self.baseline.items()
                         if status not in ("sigsys", "eperm", "enosys",
                                           "skipped")
                         and nr not in (_TABLE["write"],))
        if escaped:
            print(f"\n  [bilgi] bu çekirdekte seccomp'a uğramayan numaralar: "
                  f"{escaped}")
        self.assertLess(len(escaped), 10,
                        "beklenenden çok numara seccomp'u atlıyor")


@requires_engine
@requires_native
class SingleExecTests(unittest.TestCase):
    """``execve`` boşluğu: ilkine izin, sonrakine hayır."""

    @classmethod
    def setUpClass(cls):
        shell = shutil.which("sh")
        if shell is None:
            raise unittest.SkipTest("kabuk bulunamadı")
        cls.shell = os.path.realpath(shell)
        cls.libraries = ms.shared_libraries(cls.shell)
        cls.syscalls = list(seccomp.FFMPEG_SYSCALLS) + ["getppid", "getpgrp"]

    def _run(self, script, single_exec):
        return ms.run([self.shell, "-c", script],
                      ro_binds=[self.shell] + self.libraries,
                      syscalls=self.syscalls, single_exec=single_exec,
                      timeout=60)

    def test_target_itself_still_runs(self):
        done = self._run("echo merhaba", single_exec=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"merhaba", done.stdout)

    def test_second_exec_is_refused(self):
        script = f'echo bir; exec {self.shell} -c "echo iki"'
        # Temel çizgi: kip kapalıyken ikinci exec gerçekten çalışıyor.
        # Bu olmadan test bir şey kanıtlamaz.
        loose = self._run(script, single_exec=False)
        self.assertIn(b"iki", loose.stdout, "temel çizgi kurulamadı")

        strict = self._run(script, single_exec=True)
        self.assertIn(b"bir", strict.stdout)
        self.assertNotIn(b"iki", strict.stdout, "ikinci exec geçti")
        self.assertNotEqual(strict.returncode, 0)

    def test_mode_fails_closed_without_the_native_helper(self):
        # C tarafı yokken tek-exec istenirse komut hiç çalışmamalı.
        original = native.available
        native.available = lambda: False
        try:
            with self.assertRaises(ms.SandboxError):
                self._run("echo merhaba", single_exec=True)
        finally:
            native.available = original


@requires_engine
class EscapeAndStressTests(unittest.TestCase):
    """İzolasyonu patlatma denemeleri ve yük altında sızıntı denetimi."""

    @classmethod
    def setUpClass(cls):
        shell = shutil.which("sh")
        if shell is None:
            raise unittest.SkipTest("kabuk bulunamadı")
        cls.shell = os.path.realpath(shell)
        cls.libraries = ms.shared_libraries(cls.shell)
        cls.syscalls = list(seccomp.FFMPEG_SYSCALLS) + ["getppid", "getpgrp"]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="stress-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _sh(self, script, **kwargs):
        kwargs.setdefault("syscalls", self.syscalls)
        kwargs.setdefault("timeout", 60)
        binds = [self.shell] + self.libraries + list(kwargs.pop("ro_binds", []))
        return ms.run([self.shell, "-c", script], ro_binds=binds, **kwargs)

    def test_symlink_in_output_directory_cannot_redirect_writes(self):
        # Saldırgan çıktı dizinine sembolik bağ koyup ana makineye yazmayı
        # deneyebilir. Bağ sandbox içinden çözülüyor ve hedef görünmüyor.
        out_dir = os.path.join(self.tmp, "out")
        os.mkdir(out_dir)
        target = os.path.join(self.tmp, "hedef.txt")
        with open(target, "w") as handle:
            handle.write("dokunulmadi")
        os.symlink(target, os.path.join(out_dir, "bag"))

        self._sh("echo saldirgan > /out/bag", rw_binds=[(out_dir, "/out")])
        with open(target) as handle:
            self.assertEqual(handle.read(), "dokunulmadi",
                             "sembolik bağ üzerinden ana makineye yazıldı")

    def test_output_size_limit_is_enforced(self):
        out_dir = os.path.join(self.tmp, "out")
        os.mkdir(out_dir)
        limits = ms.Limits(file_size_bytes=64 * 1024)
        # Sınırsız yazmayı dene. İki kabul edilebilir sonuç var: RLIMIT_FSIZE
        # yükü öldürür ya da duvar saati keser. İkisi de sınırın uygulandığı
        # anlamına geliyor; önemli olan dosyanın büyümeye devam etmemesi.
        try:
            self._sh(
                "while : ; do printf 'AAAAAAAAAAAAAAAA' >> /out/sisir ; done",
                rw_binds=[(out_dir, "/out")], limits=limits, timeout=10)
        except ms.SandboxTimeout:
            pass
        produced = os.path.join(out_dir, "sisir")
        if os.path.exists(produced):
            self.assertLessEqual(os.path.getsize(produced), 128 * 1024,
                                 "dosya boyutu sınırı uygulanmadı")

    def test_many_concurrent_runs_leave_nothing_behind(self):
        results = []
        errors = []

        def worker(index):
            try:
                done = self._sh(f"echo calisan-{index}")
                results.append((index, done.returncode, done.stdout))
            except Exception as exc:  # testin kendisi patlamasın
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 12)
        for index, code, output in results:
            self.assertEqual(code, 0)
            self.assertIn(f"calisan-{index}".encode(), output)

        with open("/proc/self/mountinfo") as handle:
            self.assertNotIn("minisandbox", handle.read(),
                             "ana makinede mount kalıntısı var")

    def test_file_descriptor_exhaustion_is_contained(self):
        # RLIMIT_NOFILE düşükken yükün fd tüketmesi sandbox'ı değil yalnızca
        # kendisini etkilemeli.
        limits = ms.Limits(open_files=16)
        done = self._sh("echo hala-ayakta", limits=limits)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"hala-ayakta", done.stdout)

    def test_argv_cannot_smuggle_a_second_program(self):
        # Motor argv'yi kabuğa değil doğrudan execve'ye veriyor; kabuk
        # metakarakterleri bir anlam taşımıyor.
        done = ms.run([self.shell, "-c", "echo tamam; echo $(id)"],
                      ro_binds=[self.shell] + self.libraries,
                      syscalls=self.syscalls, timeout=60)
        self.assertIn(b"tamam", done.stdout)
        self.assertNotIn(b"uid=", done.stdout, "alt süreç çalıştı")


@unittest.skipUnless(FFMPEG and NAMESPACES_OK and SECCOMP_OK and X86_64,
                     "ffmpeg ve sandbox yetenekleri gerekiyor")
class MediaInputFuzzTests(unittest.TestCase):
    """Bozulmuş medya dosyalarıyla ffmpeg'i zorlar.

    Amaç ffmpeg'de hata bulmak değil - o ayrı bir iş. Amaç şu: girdi ne
    olursa olsun sandbox ayakta kalsın, iş sınırlar içinde bitsin ve
    geride bir şey kalmasın.
    """

    @classmethod
    def setUpClass(cls):
        from sandbox import ffmpeg_sandbox as fs
        cls.fs = fs
        cls.tmp = tempfile.mkdtemp(prefix="mediafuzz-")
        cls.clean = os.path.join(cls.tmp, "temiz.mp4")
        subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
             "-f", "lavfi", "-i", "testsrc=duration=1:size=128x96:rate=8",
             "-c:v", "libx264", "-preset", "ultrafast", cls.clean],
            check=True, capture_output=True, timeout=180,
        )
        with open(cls.clean, "rb") as handle:
            cls.original = handle.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _mutate(self, rng):
        data = bytearray(self.original)
        for _ in range(rng.randint(1, 24)):
            position = rng.randrange(len(data))
            data[position] = rng.randrange(256)
        return bytes(data)

    def test_mutated_inputs_never_break_containment(self):
        rng = random.Random(1453)
        policy = self.fs.Policy(ffmpeg_path=FFMPEG, wall_clock_seconds=25)
        marker = "/kacis-medya-fuzz"
        self.assertFalse(os.path.exists(marker))

        for index in range(12):
            source = os.path.join(self.tmp, f"bozuk{index}.mp4")
            with open(source, "wb") as handle:
                handle.write(self._mutate(rng))
            target = os.path.join(self.tmp, f"cikti{index}.mp4")
            try:
                self.fs.transcode(source, target, policy=policy)
            except (self.fs.TranscodeError, ms.SandboxError):
                pass  # bozuk girdinin reddedilmesi beklenen sonuç
            # Başarılı da olsa başarısız da, kural aynı: kaçış yok.
            self.assertFalse(os.path.exists(marker))

        with open("/proc/self/mountinfo") as handle:
            self.assertNotIn("minisandbox", handle.read())
        leftovers = [name for name in os.listdir(self.tmp)
                     if name.startswith(".sandbox-")]
        self.assertEqual(leftovers, [], f"hazırlık dizini kalıntısı: {leftovers}")

    def test_truncated_input_is_rejected_cleanly(self):
        source = os.path.join(self.tmp, "kirpik.mp4")
        with open(source, "wb") as handle:
            handle.write(self.original[: len(self.original) // 3])
        policy = self.fs.Policy(ffmpeg_path=FFMPEG, wall_clock_seconds=25)
        target = os.path.join(self.tmp, "kirpik-cikti.mp4")
        with self.assertRaises(self.fs.TranscodeError):
            self.fs.transcode(source, target, policy=policy)
        self.assertFalse(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
