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

## Katmanlar

| # | Katman | Ne engelliyor | Nasıl doğrulandı |
|---|---|---|---|
| 1 | Ayrı süreç | ffmpeg belleğindeki bir hata Flask işçisinin adres alanına (`.secret_key`, oturum anahtarı) erişemiyor | tasarım gereği: kütüphane bağlaması yok, `execve` |
| 2 | Protokol/demuxer kısıtı | `concat:`/`http:` üzerinden dosya okuma ve SSRF; sahte konteyner | `test_disguised_container_is_rejected` |
| 3 | Ad alanları (user/mount/pid/net/ipc/uts) | Veri sızdırma, ana makine dosyaları, başka süreçlere sinyal | `test_network_namespace_blocks_on_its_own` |
| 4 | Minimal salt okunur kök | Yük bırakacak yer, kabuk, `/etc`, `/proc` | `test_writing_outside_the_output_directory_fails` |
| 5 | Seccomp izin listesi | Ağ, süreç çatallama, ptrace, mount, bpf | `SeccompEnforcementTests` |
| 6 | Kaynak sınırları | Bellek bombası, sonsuz kodlama, disk doldurma | `test_wall_clock_timeout_kills_the_job` |
| 7 | AppArmor (opsiyonel) | `execve` — seccomp'un kapatamadığı boşluk | **doğrulanmadı**, aşağıya bakın |
| 8 | Çıktı doğrulaması | Beklenmeyen/çok büyük çıktı, yarım dosya | `_validate_output` |

Katmanlar birbirinin üstünü örtüyor ve bu, test yazarken bir tuzak: bir
işlevsel test iki katmanın *birleşimini* ölçer. Somut örnek — ağ testini
yazdıktan sonra `--net` bayrağını kaldıran bir mutasyon denendi ve test
**yine geçti**, çünkü seccomp ffmpeg'i `socket()` çağrısında zaten
öldürüyordu. Bu yüzden `test_network_namespace_blocks_on_its_own` seccomp'u
bilerek gevşetip ad alanını tek başına sınıyor. Her katman ayrı ayrı
kanıtlanmadıysa, aslında kaç katmanınız olduğunu bilmiyorsunuz.

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

Somut ve kapanmayan boşluk `execve`. Filtre exec'ten **önce** kuruluyor,
dolayısıyla `execve` izin listesinde kalmak zorunda — yoksa ffmpeg hiç
başlayamaz. Seccomp "ilk exec'e izin ver, sonrakileri reddet" diye bir şey
ifade edemiyor (sayaç yok). AppArmor `deny /** x` ile tam olarak bunu
söyleyebiliyor.

Pratikte bu boşluğun sömürülmesi zaten zor: kökte kabuk yok, kök salt
okunur, `/out` ve `/tmp` `noexec`, `no_new_privs` açık. Ama "zor" ile
"ifade edilmiş kural" aynı şey değil.

`sandbox/apparmor/minitube-ffmpeg` profili bu makinede **doğrulanamadı** —
çekirdekte AppArmor yok. Kuran kişi `apparmor_parser -Q` ile sözdizimini
sınamalı ve kuralları kendi dağıtımına göre gözden geçirmeli.

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

Duvar saati sınırı `unshare --kill-child` ile birlikte çalışıyor: zaman
aşımında `unshare` öldürülüyor, o da PID ad alanının 1 numaralı sürecini
götürüyor, o da içerideki her şeyi. Ölçüldü: 3 saniyelik sınır 3.0 saniyede
kesiyor, geride süreç ya da mount kalmıyor.

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
