from flask import Flask, render_template, request, redirect, send_from_directory, jsonify, flash
from werkzeug.utils import secure_filename
from datetime import datetime
import hashlib
import hmac
import json
import mimetypes
import os
import secrets

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DB_FILE = "videos.json"
SECRET_FILE = ".secret_key"

# Tarayıcıların oynatabildiği video türleri
ALLOWED_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v"}

MAX_UPLOAD_MB = int(os.environ.get("MINITUBE_MAX_UPLOAD_MB", "200"))
MAX_COMMENT_LENGTH = 1000

# Sınırı Flask'ın kendisi uygular; büyük gövde diske yazılmadan reddedilir
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)

def load_secret_key():
    # Anahtar yeniden başlatmalar arasında sabit kalmalı, yoksa beğeni
    # kimlikleri tutmaz. Önce ortam değişkeni, sonra yerel dosya.
    from_env = os.environ.get("MINITUBE_SECRET_KEY")
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
    return os.environ.get("MINITUBE_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")

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
    with open(DB_FILE, "w") as f:
        json.dump(videos, f, indent=2)

def unique_filename(filename):
    # Aynı isimli yükleme eskisinin üzerine yazmasın diye sona sayı ekliyoruz
    name, ext = os.path.splitext(filename)
    candidate = filename
    counter = 1
    while os.path.exists(os.path.join(UPLOAD_FOLDER, candidate)):
        candidate = f"{name}_{counter}{ext}"
        counter += 1
    return candidate

@app.context_processor
def inject_limits():
    return {
        "max_upload_mb": MAX_UPLOAD_MB,
        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
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

    # Kullanıcının verdiği ad doğrudan kullanılırsa uploads/ dışına yazılabilir
    filename = secure_filename(file.filename)
    if not filename:
        flash("Dosya adı geçersiz.")
        return redirect("/")

    extension = os.path.splitext(filename)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        flash("Desteklenmeyen dosya türü. İzin verilenler: " + ", ".join(sorted(ALLOWED_EXTENSIONS)))
        return redirect("/")

    filename = unique_filename(filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))

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

    flash("Video yüklendi.")
    return redirect("/")

@app.errorhandler(413)
def upload_too_large(error):
    flash(f"Dosya çok büyük. En fazla {MAX_UPLOAD_MB} MB yükleyebilirsiniz.")
    return redirect("/")

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
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == "__main__":
    # debug=True hata sayfasından kod çalıştırmaya izin verir; üretimde kapalı
    # olmalı. Açmak için MINITUBE_DEBUG=1 ile başlatın.
    app.run(
        host=os.environ.get("MINITUBE_HOST", "127.0.0.1"),
        port=int(os.environ.get("MINITUBE_PORT", "5000")),
        debug=debug_enabled()
    )
