# ffmpeg sandbox mimarisi

## Durum

MiniTube şu anda ffmpeg **kullanmıyor**; yüklenen dosyayı olduğu gibi saklayıp
`/uploads/<ad>` üzerinden sunuyor. Bu paket, işleme adımı eklendiğinde
kullanılacak izolasyon katmanını hazır tutuyor. `app.py`'ye bağlanmadı —
bağlama adımı için aşağıdaki "Entegrasyon" bölümüne bakın.

## Tehdit modeli

Yüklenen video **düşman girdisidir**. libavformat/libavcodec yüz binlerce
satır C, onlarca konteyner ve kodek ayrıştırıcısı, ve uzun bir bellek
bozulması geçmişi taşıyor. Çalışma varsayımı şu:

> Bir gün ffmpeg sürecinin içinde saldırganın kodu çalışacak.

Buradaki katmanların hiçbiri bunu **önlemiyor**. Yığın taşmasını seccomp
durdurmaz; AppArmor `memcpy`'yi denetlemez. Hepsinin yaptığı, o kodun ele
geçirdiği sürecin ne yapabileceğini daraltmak.

Bellek hatasının kendisini azaltmak ayrı ve tamamlayıcı bir iş: ffmpeg'i
güncel tutmak, dağıtımın sertleştirme bayraklarıyla derlenmiş paketini
kullanmak, ve gerekmeyen demuxer/decoder'ları derleme zamanında kapatmak
(`--disable-everything --enable-decoder=h264,aac ...`). Sonuncusu saldırı
yüzeyini en çok küçülten tek hamle ve bu depo kapsamında değil.

İkinci bir sınıf daha var ve bellek hatası bile gerektirmiyor: ffmpeg'in
playlist/concat özellikleri girdi dosyasının başka dosyalara ya da URL'lere
referans vermesine izin veriyor. Bu, doğrudan yerel dosya okuma ve SSRF
demek. 2. katman bunu kapatıyor.

## Paket düzeni

| Dosya | İş |
|---|---|
| `minisandbox.py` | İzolasyon motoru. ffmpeg'den bağımsız, herhangi bir komutu çalıştırıyor. Yalnızca stdlib. |
| `seccomp.py` | BPF filtresi üretip kuruyor. libseccomp yok. |
| `ffmpeg_sandbox.py` | ffmpeg'e özgü politika: argümanlar, kapsayıcılar, çıktı doğrulaması. |
| `apparmor/minitube-ffmpeg` | AppArmor profili. Sözdizimi ve uygulanışı CI'da sınanıyor. |
| `apparmor/selftest` | Yalnızca sınama için iki profil: biri izin veren, biri boş. |
| `native/mt_seccomp.c` | BPF üreticisinin C uygulaması + filtre kurma (TSYNC dahil). |
| `native/mt_exec_once.c` | `execve`'yi sayan çalıştırıcı: ilkine izin, sonrakine hayır. |
| `native/mt_sweep.c` | Syscall uzayını baştan sona tarayan sınama aracı. |
| `native/__init__.py` | C tarafını tembel derleyen ve yükleyen sarmalayıcı. |

Motorun ayrı olmasının pratik bir nedeni var: ffmpeg kurulu olmayan bir
makinede de sınanabiliyor. Yük olarak sistemin kendi kabuğu kullanılıyor,
tek ihtiyacı libc ve ELF yükleyicisi. CI koşucusunda gerçekten koşan kısım
bu - ffmpeg'e bağlı testler orada atlanıyor.

Hiçbir şey kurmadan denemek için:

```bash
python -m sandbox.minisandbox --demo
python -m sandbox.minisandbox --check
python -m sandbox.minisandbox --with-libs /bin/sh -c 'echo merhaba'
```

## Katmanlar

| # | Katman | Ne engelliyor | Nasıl doğrulandı |
|---|---|---|---|
| 1 | Ayrı süreç | ffmpeg belleğindeki bir hata Flask işçisinin adres alanına (`.secret_key`, oturum anahtarı) erişemiyor | tasarım gereği: kütüphane bağlaması yok, `execve` |
| 2 | Protokol/demuxer kısıtı | `concat:`/`http:` üzerinden dosya okuma ve SSRF; sahte konteyner | `test_disguised_container_is_rejected` |
| 3 | Ad alanları (user/mount/pid/net/ipc/uts) | Veri sızdırma, ana makine dosyaları, başka süreçlere sinyal | `test_network_namespace_is_empty`, `test_process_id_namespace_is_separate` |
| 4 | Minimal salt okunur kök | Yük bırakacak yer, kabuk, `/etc`, `/proc` | `test_root_is_read_only`, `test_writable_bind_is_not_executable` |
| 5 | Seccomp izin listesi | Ağ, süreç çatallama, ptrace, mount, bpf | `SeccompEnforcementTests` |
| 6 | Kaynak sınırları | Bellek bombası, sonsuz kodlama, disk doldurma | `test_timeout_kills_the_command`, `test_timeout_leaves_no_surviving_process` |
| 6b | Minimal `/dev` | - (işlevsellik) | `test_dev_null_is_a_working_character_device` |
| 7 | AppArmor (opsiyonel) | `execve` — seccomp'un kapatamadığı boşluk | `AppArmorProfileTests` (CI'da; bu makinede AppArmor yok) |
| 8 | Çıktı doğrulaması | Beklenmeyen/çok büyük çıktı, yarım dosya | `_validate_output` |

Katmanlar birbirinin üstünü örtüyor ve bu, test yazarken bir tuzak: bir
işlevsel test iki katmanın *birleşimini* ölçer. Somut örnek — ağ testini
yazdıktan sonra `--net` bayrağını kaldıran bir mutasyon denendi ve test
**yine geçti**, çünkü seccomp ffmpeg'i `socket()` çağrısında zaten
öldürüyordu. Bu yüzden `test_network_namespace_blocks_on_its_own` seccomp'u
bilerek gevşetip ad alanını tek başına sınıyor. Her katman ayrı ayrı
kanıtlanmadıysa, aslında kaç katmanınız olduğunu bilmiyorsunuz.

## C tarafı: neden var

`python -m sandbox.native` ile derleniyor, **zorunlu değil**: yoksa her şey
Python uygulamasına düşüyor ve depo çalışma zamanında derleyici
gerektirmiyor. İki şey için var.

### 1. Diferansiyel doğrulama

`mt_seccomp.c`, Python'daki `build_filter()` ile **birebir aynı** baytları
üretiyor. Amaç hız değil. Elle yazılmış bir BPF birleştiricisinde sessiz bir
hata - kayan bir etiket, sığmayan bir atlama, izin listesine yanlışlıkla
eklenmiş bir numara - ya çalışan programı öldürür ya da izolasyonda delik
bırakır, ve ikisi de normal testte kolayca gözden kaçar. İki bağımsız
uygulamayı bayt bayt karşılaştırmak o sınıfı yakalıyor: aynı hatayı iki kez
yapmak, bir kez yapmaktan çok daha zor.

Mutasyonla ölçüldü: Python tarafında izin listesine sessizce `socket`
eklemek `test_c_and_python_filters_are_identical`'ı kırıyor.

### 2. `execve` boşluğunun kapanması

Daha önce bu belgede "seccomp bunu ifade edemiyor, AppArmor kapatıyor"
yazıyordu. Artık seccomp da kapatabiliyor.

Filtre exec'ten *önce* kurulduğu için `execve` izin listesinde kalmak
zorunda; ve BPF'te sayaç yok, yani "ilkine izin ver, sonrakini reddet"
yazılamıyor. `SECCOMP_RET_USER_NOTIF` kararı bir denetçi sürece bırakıyor ve
denetçi sayabiliyor. `mt_exec_once.c` şunu yapıyor:

```
socketpair -> fork
  |- çocuk (hedef): filtreyi NEW_LISTENER ile kurar, execve eder
  `- ebeveyn (denetçi): ilk execve'ye CONTINUE, kalanlara EPERM
```

Sıra önemli: seccomp filtreleri fork'ta miras alınıyor, o yüzden denetçi
filtre kurulmadan **önce** fork ediliyor.

Ölçüldü - aynı komut, aynı sandbox:

| | ikinci `exec` |
|---|---|
| `single_exec=False` | çalışıyor, çıktı görünüyor |
| `single_exec=True` | `Operation not permitted`, rc=126 |

İlk tasarım bildirim fd'sini SCM_RIGHTS ile yolluyordu ve **çalışmadı**:
fd'yi üretmek için filtre kurulmak zorunda, ama kurulduktan sonra hedef
artık `sendmsg` çağıramıyor - listede yok ve olmaması gerekiyor. Hedef
orada SIGSYS ile ölüyordu. Çözüm ters yönde: hedef fd'yi yollamıyor, denetçi
`pidfd_getfd` ile alıyor. Hedefin filtre kurulduktan sonra ihtiyaç duyduğu
tek şey bir `write` ve bir `fcntl`.

TOCTOU notu: USER_NOTIF ile syscall argümanlarını okumak klasik bir tuzak.
Buradaki denetçi hiçbir argümana bakmıyor, yalnızca sayıyor - karar
argümandan bağımsız olduğu için o sınıf hata yok.

Sınırı: bu bir ayrıcalık sınırı değil, sertleştirme katmanı. Denetçi hedefle
aynı ad alanında ve aynı kullanıcıda. Değeri, ele geçirilmiş bir ffmpeg'in
"kabuk çağır" adımını kesmesi.

## Fuzzing ve stres paketi

`test_fuzz.py`. Dört başlık: diferansiyel filtre fuzz'ı, kapsamlı syscall
taraması, tek-exec kuralı, kaçış/stres.

### Kapsamlı tarama neyi buldu

Tek tek yazılmış testler yalnızca akla gelen syscall'ları kapsıyor.
`mt_sweep` 0'dan 460'a kadar **her** numarayı deniyor: her numara için bir
süreç çatallanıyor (filtre geri alınamaz), filtre kuruluyor, çağrı yapılıyor
ve sonuç bildiriliyor. Ad alanlarının içinde koşuyor, çünkü sıfır argümanlı
bir syscall çoğu zaman EFAULT ile döner ama hepsi değil.

Bulgu: **bazı syscall numaraları hiçbir seccomp filtresine uğramıyor** ve
hangileri olduğu makineye göre değişiyor. Bu deponun geliştirildiği
çekirdekte 335 ve 336; GitHub koşucusunda yalnızca 335. İki ayrı makinede
ölçüldü ve sabit bir istisna listesinin neden yanlış olacağını da bu
gösteriyor - iki makineden birinde mutlaka hatalı olurdu.

#### 335 ve 336 ne

İlk turda bu "nedeni çözülemedi" diye bırakılmıştı. Sonradan ölçüldü;
aşağıdakilerin hepsi depo kodundan bağımsız, tek dosyalık C programlarıyla
yeniden üretildi.

**Bu numaralar boşluk değil, uygulanmış çağrılar.** Gerçekten tahsis
edilmemiş bir komşu (337) `ENOSYS` veriyor. 335 ve 336 vermiyor:

| numara | filtre yok | varsayılan `ERRNO(EPERM)` | varsayılan `KILL_PROCESS` |
|---|---|---|---|
| 334 (`rseq`) | EINVAL | **EPERM** | **SIGSYS** |
| 335 | SIGILL | SIGILL | SIGILL |
| 336 | ENXIO | ENXIO | ENXIO |
| 337 (tahsissiz) | ENOSYS | **EPERM** | **SIGSYS** |

Aynı süreçte, tek ve canlı bir filtreyle ölçüldü, yani "filtre kurulmamıştı"
ihtimali yok: 334 ve 337 filtreye takılırken 335/336 takılmıyor. `prctl` ve
`seccomp(2)+TSYNC` yollarının ikisinde de aynı.

**Atlanan şey yalnızca seccomp.** `PTRACE_SYSCALL` bu iki numara için giriş
ve çıkış duraklarını normal şekilde veriyor (`orig_rax` = 335/336). Yani
genel syscall giriş yolu işliyor, atlanan katman seccomp'a özgü.

**335'i öldüren şey filtre değil, çağrının kendi uygulaması.** SIGILL
yakalanıp `siginfo` okunduğunda `si_code = SI_KERNEL`, `si_addr = 0` çıkıyor -
bu, çekirdeğin `force_sig(SIGILL)` çağırdığı anlamına gelir, CPU'nun geçersiz
komuta takılması değil. `strace` altında dönüş değeri de görünüyor: düz `-1`
(strace bunu `EPERM` diye yazıyor, çünkü `EPERM == 1`). Yani uygulama
"sinyal gönder ve -1 dön" şeklinde.

**Muhtemelen `uretprobe` ve `uprobe`.** Çekirdek imajında tam olarak bu iki
yeni x86_64 çağrısı var:

```
$ grep -E '__x64_sys_u(ret)?probe' /proc/kallsyms
ffffffff812aef00 T __x64_sys_uretprobe
ffffffff812af160 T __x64_sys_uprobe
```

Bunlar "gerçek" syscall değil, uprobe trampolininden çağrılmak üzere var
olan giriş noktaları; trampolin bağlamı dışında çağrıldıklarında çağıranı
reddetmeleri beklenir - ölçülen davranış (335 çağıranı öldürüyor, 336 "böyle
bir aygıt yok" diyor) buna uyuyor. Koşucudaki daha eski çekirdekte yalnızca
335'in anormal olması da uyuyor: `uretprobe` önce, `uprobe` sonra eklendi.

Bunu **çıkarım** olarak yazıyorum, kanıt olarak değil: numara→ad eşleşmesini
çekirdek kaynağından doğrulayamadım (bu ortamda dış ağ kapalı, `/proc/kcore`
yok, `sys_call_table` kallsyms'te görünmüyor, kurulu `strace` 6.8 bu adları
henüz bilmiyor ve `syscall_0x14f` yazıyor). Seccomp'un neden özellikle bu iki
numarayı atladığını da kaynaktan okuyup doğrulayamadım.

**Güvenlik açısından ne anlama geliyor.** Filtrenin "izin listesi dışında
hiçbir şey geçmez" güvencesinin ölçülmüş bir istisnası var. Ama istisna
sömürülebilir değil: iki çağrıdan biri çağıranı öldürüyor (sandbox'ta zaten
istenen sonuç), diğeri hata dönüyor. 336'nın anlamlı bir iş yapması için
adres uzayında bir uprobe trampolini bulunması gerekir; onu kurmak
`perf_event_open` veya `bpf` ister ve ikisi de izin listesinde **değil**.
Yani içerideki bir yük bu numaralarla yeni bir yetenek kazanmıyor.

Filtrenin mantığı da doğru: Python'da yazılmış küçük bir BPF yorumlayıcısı
336 için `KILL` döndürüyor. Program doğru, çekirdek onu bu iki numara için
uygulamıyor.

Test bu yüzden sabit bir istisna listesi yazmıyor - yazsaydı iki
makineden birinde yanlış olurdu. Temel çizgi, **aynı
üreticiyle** yapılmış neredeyse boş bir filtre (`write` + `exit_group`):
önce bu çekirdekte gerçekten durdurulabilen numaralar ölçülüyor, sonra
gerçek filtrenin onların hepsini durdurduğu doğrulanıyor. Böylece
karşılaştırma "izin listem fazla geniş mi" sorusunu "bu çekirdekte ne
oluyor" sorusundan ayırıyor ve test başka makinelerde de doğru kalıyor.

Geri kalan 458 numara tam olarak beklendiği gibi: izin listesindekiler
geçiyor, `fork`/`vfork` EPERM, `clone3` ENOSYS, diğer her şey SIGSYS.

### Diğer başlıklar

* **Filtre fuzz'ı** - rastgele izin listeleriyle 300 program üretiliyor;
  hepsi RET ile bitmeli, her izinli syscall kodlanmış olmalı, üretim
  deterministik ve sıralamadan bağımsız olmalı, C ile birebir aynı çıkmalı.
* **Kaçış denemeleri** - çıktı dizinine konan sembolik bağla ana makineye
  yazmak, dosya boyutu sınırını aşmak, fd tüketmek, argv üzerinden ikinci
  program kaçırmak.
* **Stres** - 12 eşzamanlı sandbox koşusu, ardından mount/süreç sızıntısı
  denetimi.
* **Medya fuzz'ı** (ffmpeg gerekiyor) - geçerli bir mp4'ün baytları rastgele
  bozularak 12 tur besleniyor. Amaç ffmpeg'de hata bulmak değil; girdi ne
  olursa olsun sandbox'ın ayakta kalması, işin sınırlar içinde bitmesi ve
  geride kalıntı olmaması.

## Seccomp: izin listesi nasıl belirlendi

Tahminle değil ölçümle:

```bash
strace -f -c -o trace.txt ffmpeg -i in.mp4 -c:v libx264 -c:a aac out.mp4
awk 'NR>2 && $NF!="total" {print $NF}' trace.txt | sort -u
```

Statik ffmpeg 7.0 ile çıkan küme 32 syscall. Üstüne yalnızca kapanış yolu ve
libc varyantları eklendi (`exit_group`, `rt_sigreturn`, `newfstatat`/`statx`
gibi aynı işin farklı isimleri). Başka bir ffmpeg derlemesine geçilirse
ölçüm tekrarlanmalı.

İki ayrıntı ölçüm sırasında ortaya çıktı:

**`clone` bayrağa göre ayrılıyor.** ffmpeg iş parçacığı açmak için `clone`
çağırıyor; yeni *süreç* açmak da aynı syscall. Seccomp tamsayı argümanlara
bakabildiği için `CLONE_THREAD` biti denetleniyor: iş parçacığı serbest,
çatallanma `EPERM`. Öldürmek yerine `EPERM` dönmesi bilinçli — meşru bir
iş parçacığı açma yanlışlıkla ölümcül olmasın.

**`clone3` ENOSYS dönmek zorunda.** glibc ≥ 2.34 `pthread_create` için önce
`clone3` deniyor; bayrakları bir yapı işaretçisiyle aldığı için seccomp
içeriğine bakamıyor. Ölçüldü: `clone3` reddedilince iş parçacığı açan her
süreç `SIGSYS` alıyor. `ENOSYS` döndürülünce glibc eski `clone`'a düşüyor ve
bayrak denetimi yeniden mümkün oluyor. Docker'ın varsayılan profili de aynı
şeyi yapıyor.

## Seccomp'un yapamadığı, AppArmor'ın yaptığı

Seccomp yol denetimi yapamıyor: syscall argümanı bir işaretçi ve çekirdek
filtresi onun arkasındaki dizeyi güvenle okuyamıyor (TOCTOU). Yani "`openat`
serbest ama yalnızca `/in` altında" seccomp'la yazılamıyor. Bu depoda o işi
mount ad alanı yapıyor: başka bir şey zaten görünmüyor.

Somut boşluk `execve`. (Artık `single_exec=True` ile kapatılabiliyor -
yukarıdaki "C tarafı" bölümüne bakın. Aşağıdaki açıklama o kip kapalıyken
geçerli.) Filtre exec'ten **önce** kuruluyor,
dolayısıyla `execve` izin listesinde kalmak zorunda — yoksa ffmpeg hiç
başlayamaz. Seccomp "ilk exec'e izin ver, sonrakileri reddet" diye bir şey
ifade edemiyor (sayaç yok). AppArmor `deny /** x` ile tam olarak bunu
söyleyebiliyor.

Pratikte bu boşluğun sömürülmesi zaten zor: kökte kabuk yok, kök salt
okunur, `/out` ve `/tmp` `noexec`, `no_new_privs` açık. Ama "zor" ile
"ifade edilmiş kural" aynı şey değil.

`sandbox/apparmor/minitube-ffmpeg` profili bu deponun geliştirildiği
makinede doğrulanamıyor - çekirdekte AppArmor yok. Doğrulama CI'ya taşındı;
koşucuda AppArmor etkin. Orada üç şey sınanıyor:

1. **Sözdizimi.** `apparmor_parser -Q` gerçek profili ayrıştırıyor.
2. **Uygulanışı.** "Profil yüklendi" ile "profil iş görüyor" aynı şey değil
   ve geçiş isteğinin kabul edilmesi de kanıt değil - AppArmor'suz bir
   çekirdekte o yazma sessizce başarılı oluyor. Tek sağlam kanıt fark:
   `apparmor/selftest` iki profil yüklüyor, biri kabuğun çalışmasına izin
   veriyor, diğerinde hiç kural yok. Aynı komut ikisiyle çalıştırılıyor;
   sonuçlar aynı çıkarsa AppArmor uygulanmıyor demektir ve test kırılır.
3. **Fail-closed.** Yüklü olmayan bir profil istendiğinde iş çalışmıyor.

Profillerin yüklenemediği bir koşucuda testler atlanıyor, sessizce "geçti"
demiyorlar - CI adımı durumunu `MINITUBE_APPARMOR_SELFTEST` ile bildiriyor.
Yine de `deny /** x` kuralının gerçek ffmpeg iş yükünde davranışı ayrı bir
soru; sınanan şey mekanizmanın uygulandığı.

Buna karşılık AppArmor'ın *fail-closed* davranışı doğrulandı ve yolda bir
hata bulundu: AppArmor olmayan bir çekirdekte `/proc/self/attr/exec` yine
duruyor ve yazma **sessizce başarılı oluyor**. Yani "profil isteği yazıldı"
tek başına kanıt değil. Sarmalayıcı artık önce AppArmor'ın gerçekten etkin
olduğunu doğruluyor; değilse iş hiç başlamıyor
(`test_apparmor_request_without_apparmor_fails_closed`).

## Kaynak sınırları

`memory_bytes` RLIMIT_AS'e gidiyor, yani *sanal adres alanını* sınırlıyor.
x264 cömert rezervasyon yaptığı için gerçek kullanımla arası açık: 1 GiB'de
`pthread_create` EAGAIN veriyor, 2 GiB'de aynı iş 0.1 saniyede bitiyor.
Varsayılan ölçülerek seçildi. Gerçek bellek tavanı isteniyorsa doğru araç
cgroup `memory.max`; o da devredilmiş bir cgroup ağacı gerektiriyor ve bu
paketin kapsamında değil.

Duvar saati sınırında süreç kendi oturumunda başlatılıp grup komple
öldürülüyor. Bunun gerekçesi somut: önceki sürümde zaman aşımı yalnızca
`unshare`'i öldürüyordu ve meşgul döngüdeki yük her koşuda hayatta kalıp CPU
yakmaya devam ediyordu. Hangi değişikliğin tek başına yettiğini izole
edemedim - kısmi geri almalarla sızıntıyı yeniden üretemedim - o yüzden
burada bir mekanizma suçlanmıyor; istenen davranış açıkça kuruluyor ve
`test_timeout_leaves_no_surviving_process` onu koruyor.

## Fail-closed

İzolasyon katmanları kurulamıyorsa ffmpeg **hiç çalıştırılmıyor**.
`check_capabilities()` eksikleri sayıyor ve `transcode()` `SandboxError` ile
duruyor. Korumasız çalıştırmak en kötü sonuç olurdu: sistem sandbox'lı
sanılırken değil.

```bash
python -m sandbox.ffmpeg_sandbox --check --ffmpeg /usr/bin/ffmpeg
```

## Serbest argüman yok

`transcode()` çağıranın ffmpeg argümanı vermesine izin vermiyor; yalnızca
adlandırılmış profiller (`PROFILES`) var. Serbest argüman başlı başına bir
enjeksiyon yüzeyi: `-i http://...`, `-f lavfi -i ...`, `-protocol_whitelist
all` gibi değerler 2. katmanın üstünden atlar. Yeni bir ihtiyaç çıkarsa
doğru hamle yeni bir profil eklemek.

## Entegrasyon

`app.py`'ye bağlarken dikkat edilecekler:

- Yükleme isteği içinde **senkron** çağırmayın. Yeniden kodlama saniyeler
  sürüyor ve `python app.py` tek istek işliyor. Bir kuyruk ya da arka plan
  işçisi gerekiyor; bu, `videos.json`'un tüm dosyayı yeniden yazan yapısıyla
  birlikte düşünülmeli (bkz. kök `CLAUDE.md`).
- Girdi `uploads/` içindeki dosya, çıktı da oraya; `transcode()` çıktıyı
  hedefin yanında hazırlayıp `os.replace` ile koyuyor, yani `save_videos()`
  ile aynı atomik yerine koyma deseni.
- `videos.json` şemasına yeni alan eklenecekse (ör. `processed`) varsayılanı
  `normalize_video()` içine koyun, rotaya değil.
- ffmpeg kurulu değilse `check_capabilities()` bunu söylüyor; yükleme yolunun
  o durumda ne yapacağına (ham dosyayı sunmak mı, yüklemeyi reddetmek mi)
  karar verilmeli. Bu bir ürün kararı, sessizce seçilmemeli.

## Gereksinimler

- Linux, x86_64 (seccomp syscall tablosu mimariye özgü)
- `unshare(1)` (util-linux)
- Ayrıcalıksız kullanıcı ad alanı açık
  (`/proc/sys/user/max_user_namespaces` > 0)
- Seccomp filtre desteği
- İsteğe bağlı: AppArmor

Başka bir mimariye taşımak için `seccomp.SYSCALLS_X86_64` tablosunun ve
`AUDIT_ARCH_X86_64` sabitinin o mimari için karşılığı gerekiyor. Yanlış
mimaride filtre kurmak sessizce yanlış syscall'lara izin vereceği için
`build_filter` mimari uyuşmazlığında süreci öldürüyor.

## Demo neyin ortaya çıkardı

Motoru ffmpeg'den ayırıp çıplak bir kabukla denemek üç hata gösterdi. Üçü de
ffmpeg ile fark edilmemişti, çünkü ffmpeg o yolları hiç kullanmıyor:

1. **`/dev` yoktu.** `2>/dev/null` gibi çok yaygın bir deyim kırılıyordu ve
   suç sandbox'a yıkılıyordu. Artık minimal bir `/dev` bağlanıyor -
   `MS_NODEV` **olmadan**, yoksa çekirdek aygıt semantiğini yok sayar ve
   `/dev/null` sıradan bir dosya gibi davranır.
2. **`fork` ile `clone` farklı sonuçlanıyordu.** Aynı niyet (süreç açmak)
   libc'nin hangi syscall'ı seçtiğine göre bir öldürme bir `EPERM`
   veriyordu. İkisi de artık `EPERM`.
3. **Zaman aşımı yükü öldürmüyordu.** Meşgul döngüdeki kabuk her koşuda
   hayatta kalıp CPU yakmaya devam ediyordu. Artık yeni oturum açılıp grup
   komple öldürülüyor ve bir regresyon testi bunu koruyor.

Ayrıca ölçüm sırasında iki kez kendi harness'ım yanılttı: bir kez sandbox
dışında çalıştırdığım betiğin yazdığı dosyayı "kaçış" sandım, bir kez de
sızıntı belirtecim kendi kabuk komut satırımda geçtiği için kendi
harness'ımı sızıntı saydım. İkisi de aynı dersi veriyor - bir güvenlik
testinin önce *temel çizgisi* kurulmalı, yoksa neyi ölçtüğü belirsiz.

## Kalan riskler

- **Çekirdek hâlâ saldırı yüzeyi.** İzin listesindeki her syscall bir
  çekirdek giriş noktası. Kullanıcı ad alanları da tarihsel olarak ayrıcalık
  yükseltme kaynağı oldu.
- **`execve` seccomp tarafında açık** (yukarıya bakın).
- **AppArmor profili sınanmadı.**
- **Yan kanallar kapsam dışı.** Aynı makinedeki başka süreçlere karşı
  zamanlama/önbellek saldırıları düşünülmedi.
- **ffmpeg'in kendisi sabitlenmiş değil.** Depodaki kilit Python paketlerini
  kapsıyor; ffmpeg ikilisi işletim sisteminden geliyor.
