from flask import Flask, render_template, request, redirect, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import os
import json
import uuid
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DB_FILE = "videos.json"

# Sadece video uzantıları: uploads/ aynı origin'den servis edildiği için
# .html/.svg gibi dosyalar yüklenirse saklı XSS'e dönüşür.
ALLOWED_EXTENSIONS = {".mp4", ".webm", ".ogg", ".ogv", ".mov", ".m4v"}

# Yükleme boyutu sınırı (varsayılan 256 MB)
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "256"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)

def load_videos():
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_videos(videos):
    with open(DB_FILE, "w") as f:
        json.dump(videos, f, indent=2)

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

    return f"{base}-{uuid.uuid4().hex[:8]}{ext}"

@app.errorhandler(413)
def upload_too_large(e):
    return f"Video çok büyük (en fazla {MAX_UPLOAD_MB} MB)", 413

@app.route("/")
def home():
    videos = load_videos()
    return render_template("index.html", videos=videos)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("video")
    title = request.form.get("title", "").strip()

    if file and file.filename != "" and title:
        filename = build_safe_filename(file.filename)
        if filename is None:
            return redirect("/")

        file.save(os.path.join(UPLOAD_FOLDER, filename))

        videos = load_videos()
        videos.append({
            "title": title,
            "filename": filename,
            "views": 0,
            "likes": 0,
            "liked_by": [],
            "comments": []          # ← yorum listesi
        })
        save_videos(videos)

    return redirect("/")

@app.route("/watch/<filename>")
def watch(filename):
    videos = load_videos()
    user_ip = request.remote_addr

    for video in videos:
        if video["filename"] == filename:
            video["views"] += 1

            # Eski videolarda eksik alanları tamamla
            if "likes" not in video:
                video["likes"] = 0
            if "liked_by" not in video:
                video["liked_by"] = []
            if "comments" not in video:
                video["comments"] = []

            save_videos(videos)

            already_liked = user_ip in video["liked_by"]

            return render_template("watch.html", video=video, already_liked=already_liked)

    return "Video bulunamadı", 404

@app.route("/like/<filename>", methods=["POST"])
def like(filename):
    videos = load_videos()
    user_ip = request.remote_addr

    for video in videos:
        if video["filename"] == filename:
            if "likes" not in video:
                video["likes"] = 0
            if "liked_by" not in video:
                video["liked_by"] = []

            if user_ip in video["liked_by"]:
                video["liked_by"].remove(user_ip)
                video["likes"] -= 1
                liked = False
            else:
                video["liked_by"].append(user_ip)
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

    videos = load_videos()
    user_ip = request.remote_addr

    for video in videos:
        if video["filename"] == filename:
            if "comments" not in video:
                video["comments"] = []

            video["comments"].append({
                "text": text,
                "ip": user_ip,  # gizli tutuyoruz
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
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=int(os.environ.get("PORT", "5000")), debug=debug)
