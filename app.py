from flask import Flask, render_template, request, redirect, send_from_directory, jsonify, flash, session
from werkzeug.utils import secure_filename
from collections import defaultdict, deque
from datetime import datetime
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import tempfile
import threading
import time
import uuid

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DB_FILE = "videos.json"
SECRET_FILE = ".secret_key"

# Sadece video uzantıları: uploads/ aynı origin'den servis edildiği için
# .html/.svg gibi dosyalar yüklenirse saklı XSS'e dönüşür.
ALLOWED_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v"}

# Yükleme boyutu sınırı (varsayılan 256 MB)
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "256"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

MAX_COMMENT_LENGTH = 1000

# Dosya sistemi ad sınırı (NAME_MAX). Aşılırsa file.save() OSError verir.
MAX_FILENAME_LENGTH = 255

# Tarayıcı çerezi başka sitelerden gelen POST'lara eklemesin. Token asıl
# koruma; bu ikinci katman.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Token gerektirmeyen, durum değiştirmeyen yöntemler
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Uç başına (istek sayısı, saniye) sınırı. Yükleme diski doldurabildiği için
# en dar sınır onda. Kimlik yok, o yüzden istemci başına sayıyoruz.
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "3600"))
RATE_LIMITS = {
    "upload": int(os.environ.get("RATE_LIMIT_UPLOAD", "10")),
    "comment": int(os.environ.get("RATE_LIMIT_COMMENT", "30")),
    "like": int(os.environ.get("RATE_LIMIT_LIKE", "60")),
}

# Süresi geçmiş kayıtları ne sıklıkla süpüreceğimiz
RATE_SWEEP_INTERVAL = 300

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)

def load_secret_key():
    # Anahtar yeniden başlatmalar arasında sabit kalmalı, yoksa beğeni
    # kimlikleri tutmaz. Önce ortam değişkeni, sonra yerel dosya.
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        return from_env.encode()

    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "rb") as f:
            saved = f.read().strip()
        if saved:
            return saved

    generated = secrets.token_hex(32).encode()
    with open(SECRET_FILE, "wb") as f:
        f.write(generated)
    os.chmod(SECRET_FILE, 0o600)
    return generated

SECRET_KEY = load_secret_key()
app.secret_key = SECRET_KEY

def viewer_id(ip):
    # IP'yi düz metin saklamıyoruz. IPv4 uzayı küçük olduğu için düz karma
    # kırılabilirdi; gizli anahtarlı HMAC anahtar olmadan geri çevrilemez.
    return hmac.new(SECRET_KEY, (ip or "").encode(), hashlib.sha256).hexdigest()[:32]

def is_viewer_id(value):
    return (
        isinstance(value, str)
        and len(value) == 32
        and all(c in "0123456789abcdef" for c in value)
    )

def debug_enabled():
    return os.environ.get("FLASK_DEBUG", "0") == "1"

def csrf_token():
    # Oturum başına tek token. Formlara gizli alan, fetch'e X-CSRF-Token
    # başlığı olarak gidiyor. Çerez imzalı olduğu için istemci uyduramaz.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.before_request
def verify_csrf():
    # Varsayılan kapalı: durum değiştiren her istek token istiyor, böylece
    # ileride eklenen bir POST rotası kendiliğinden korunmuş oluyor.
    if request.method in SAFE_METHODS:
        return None

    expected = session.get("csrf_token", "")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")

    # compare_digest str verilirse ASCII dışı girdide TypeError atıyor;
    # bayta çevirip hem bunu hem zamanlama sızıntısını kapatıyoruz.
    if expected and hmac.compare_digest(
        sent.encode("utf-8", "replace"), expected.encode("utf-8")
    ):
        return None

    if request.endpoint == "like":
        return jsonify({"error": "Geçersiz veya eksik CSRF anahtarı"}), 403
    return "Geçersiz veya eksik CSRF anahtarı", 403

# İstek zaman damgaları: (uç, viewer_id) -> deque[float]. Süreç içi tutuluyor,
# yani birden çok worker ile çalıştırılırsa her worker kendi sayacını tutar ve
# yeniden başlatmada sıfırlanır. Tek süreçlik bu uygulama için yeterli.
_rate_hits = defaultdict(deque)
_rate_lock = threading.Lock()
_last_sweep = 0.0

def _now():
    # Testlerin zamanı ileri sarabilmesi için tek nokta
    return time.monotonic()

def _sweep_expired(now):
    # Çağıran _rate_lock'u tutuyor olmalı. Süpürme olmazsa sözlük, saldırganın
    # kullandığı her yeni IP için kalıcı bir kayıt biriktirirdi.
    global _last_sweep
    if now - _last_sweep < RATE_SWEEP_INTERVAL:
        return
    _last_sweep = now

    for key in list(_rate_hits):
        hits = _rate_hits[key]
        while hits and hits[0] <= now - RATE_LIMIT_WINDOW:
            hits.popleft()
        if not hits:
            del _rate_hits[key]

def rate_limit_retry_after(endpoint, viewer):
    """İzin varsa None döner ve isteği sayar.

    Sınır aşıldıysa isteği saymadan, kaç saniye sonra tekrar denenebileceğini
    döndürür.
    """
    limit = RATE_LIMITS[endpoint]
    now = _now()

    with _rate_lock:
        _sweep_expired(now)

        hits = _rate_hits[(endpoint, viewer)]
        while hits and hits[0] <= now - RATE_LIMIT_WINDOW:
            hits.popleft()

        if len(hits) >= limit:
            return max(1, int(hits[0] + RATE_LIMIT_WINDOW - now))

        hits.append(now)
        return None

@app.before_request
def enforce_rate_limit():
    # CSRF kancasından sonra çalışıyor: sahte istek kurbanın kotasını yakmasın.
    if request.method in SAFE_METHODS or request.endpoint not in RATE_LIMITS:
        return None

    retry_after = rate_limit_retry_after(request.endpoint, viewer_id(request.remote_addr))
    if retry_after is None:
        return None

    message = f"Çok fazla istek. {retry_after} saniye sonra tekrar deneyin."
    if request.endpoint == "like":
        response = jsonify({"error": message})
    else:
        response = app.make_response(message)
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response

def normalize_video(video):
    # Eski kayıtlarda eksik alanları tamamlar ve düz IP kalıntılarını siler.
    # Değişiklik olduysa True döner, çağıran taraf dosyayı bir kez yazar.
    changed = False

    for field, default in (("views", 0), ("likes", 0)):
        if field not in video:
            video[field] = default
            changed = True

    for field in ("liked_by", "comments"):
        if field not in video:
            video[field] = []
            changed = True

    # Beğeniler eskiden düz IP olarak tutuluyordu
    migrated = [entry if is_viewer_id(entry) else viewer_id(entry) for entry in video["liked_by"]]
    if migrated != video["liked_by"]:
        video["liked_by"] = migrated
        changed = True

    # Yorumların içine IP yazılıyordu; bu alanı kimse okumuyor
    for comment in video["comments"]:
        if "ip" in comment:
            del comment["ip"]
            changed = True

    if video["likes"] < 0:
        video["likes"] = 0
        changed = True

    return changed

def load_videos():
    with open(DB_FILE, "r") as f:
        videos = json.load(f)

    changed = False
    for video in videos:
        if normalize_video(video):
            changed = True

    if changed:
        save_videos(videos)

    return videos

def save_videos(videos):
    # Doğrudan DB_FILE'a yazmak dosyayı önce sıfırlar: o aralıkta okuyan bir
    # istek yarım JSON görür, yazarken süreç ölürse dosya kalıcı bozulur ve
    # tüm rotalar 500 döner. Aynı dizine geçici dosya yazıp atomik olarak
    # yerine koyuyoruz; okuyucu ya eski ya yeni dosyanın tamamını görür.
    directory = os.path.dirname(os.path.abspath(DB_FILE)) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".videos-", suffix=".json")

    try:
        with os.fdopen(fd, "w") as f:
            json.dump(videos, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        # mkstemp 0600 veriyor; mevcut dosyanın iznini koruyalım
        if os.path.exists(DB_FILE):
            os.chmod(temp_path, os.stat(DB_FILE).st_mode & 0o777)
        else:
            os.chmod(temp_path, 0o644)

        os.replace(temp_path, DB_FILE)
    except BaseException:
        # KeyboardInterrupt de dahil: geride yarım geçici dosya bırakmayalım
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

def build_safe_filename(original_name):
    """Yüklenen dosya adını güvenli ve benzersiz hale getirir.

    secure_filename dizin geçişini (../) engeller, uuid eki ise aynı adlı
    yüklemelerin birbirini ezmesini önler. Uzantı izin listesinde değilse
    None döner.
    """
    cleaned = secure_filename(original_name or "")
    base, ext = os.path.splitext(cleaned)
    ext = ext.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return None

    if not base:
        base = "video"

    # Uzun adı kısaltıyoruz: NAME_MAX aşılırsa file.save() OSError ile
    # patlıyor ve istek 500 dönüyordu. Benzersizliği uuid eki sağladığı için
    # tabanı kırpmak güvenli. secure_filename yalnızca ASCII ürettiğinden
    # karakter sayısı bayt sayısına eşit.
    suffix = f"-{uuid.uuid4().hex[:8]}{ext}"
    base = base[:MAX_FILENAME_LENGTH - len(suffix)] or "video"

    return f"{base}{suffix}"

@app.context_processor
def inject_limits():
    return {
        "max_upload_mb": MAX_UPLOAD_MB,
        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
        "csrf_token": csrf_token(),
    }

@app.route("/")
def home():
    videos = load_videos()
    return render_template("index.html", videos=videos)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("video")
    title = request.form.get("title", "").strip()

    if not file or file.filename == "" or not title:
        flash("Başlık ve video dosyası zorunlu.")
        return redirect("/")

    # Diske yazılan ad her zaman bu yardımcıdan geçer
    filename = build_safe_filename(file.filename)
    if filename is None:
        flash("Desteklenmeyen dosya türü. İzin verilenler: " + ", ".join(sorted(ALLOWED_EXTENSIONS)))
        return redirect("/")

    saved_path = os.path.join(UPLOAD_FOLDER, filename)

    # Dosya diske yazıldıktan sonra kayıt yazımı patlarsa (disk dolu, bozuk
    # videos.json) dosya erişilemez halde diskte kalırdı. Kayıt tamamlanamazsa
    # dosyayı da geri alıyoruz; başarılı akış aynen eskisi gibi.
    try:
        file.save(saved_path)

        videos = load_videos()
        videos.append({
            "title": title,
            "filename": filename,
            "views": 0,
            "likes": 0,
            "liked_by": [],
            "comments": []
        })
        save_videos(videos)
    except BaseException:
        try:
            os.remove(saved_path)
        except OSError:
            pass
        raise

    flash("Video yüklendi.")
    return redirect("/")

@app.errorhandler(413)
def upload_too_large(error):
    # Durum kodu 413 kalıyor; mesajı da ana sayfada gösteriyoruz
    flash(f"Video çok büyük (en fazla {MAX_UPLOAD_MB} MB)")
    return render_template("index.html", videos=load_videos()), 413

@app.route("/watch/<filename>")
def watch(filename):
    videos = load_videos()
    viewer = viewer_id(request.remote_addr)

    for video in videos:
        if video["filename"] == filename:
            video["views"] += 1
            save_videos(videos)

            return render_template(
                "watch.html",
                video=video,
                already_liked=viewer in video["liked_by"],
                video_mimetype=mimetypes.guess_type(filename)[0] or "video/mp4"
            )

    return "Video bulunamadı", 404

@app.route("/like/<filename>", methods=["POST"])
def like(filename):
    videos = load_videos()
    viewer = viewer_id(request.remote_addr)

    for video in videos:
        if video["filename"] == filename:
            if viewer in video["liked_by"]:
                video["liked_by"].remove(viewer)
                video["likes"] -= 1
                liked = False
            else:
                video["liked_by"].append(viewer)
                video["likes"] += 1
                liked = True

            if video["likes"] < 0:
                video["likes"] = 0

            save_videos(videos)
            return jsonify({
                "likes": video["likes"],
                "liked": liked
            })

    return jsonify({"error": "Video bulunamadı"}), 404

@app.route("/comment/<filename>", methods=["POST"])
def comment(filename):
    text = request.form.get("comment", "").strip()
    if not text:
        return redirect(f"/watch/{filename}")

    text = text[:MAX_COMMENT_LENGTH]

    videos = load_videos()

    for video in videos:
        if video["filename"] == filename:
            # Yorumda IP tutmuyoruz; kimliğe götürecek hiçbir alan saklanmıyor
            video["comments"].append({
                "text": text,
                "time": datetime.now().strftime("%d.%m.%Y %H:%M")
            })
            save_videos(videos)
            break

    return redirect(f"/watch/{filename}")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    # send_from_directory dizin dışına çıkan yolları kendisi reddeder.
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.after_request
def add_security_headers(response):
    # Tarayıcı, servis edilen dosyanın tipini tahmin etmeye çalışmasın.
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

if __name__ == "__main__":
    # Varsayılan olarak sadece localhost ve debug kapalı. Werkzeug debugger'ı
    # uzaktan erişilebilir olursa kod çalıştırmaya izin verir.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=debug_enabled()
    )
