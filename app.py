from flask import Flask, render_template, request, redirect, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
DB_FILE = "videos.json"

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

def unique_filename(filename):
    # Aynı isimli yükleme eskisinin üzerine yazmasın diye sona sayı ekliyoruz
    name, ext = os.path.splitext(filename)
    candidate = filename
    counter = 1
    while os.path.exists(os.path.join(UPLOAD_FOLDER, candidate)):
        candidate = f"{name}_{counter}{ext}"
        counter += 1
    return candidate

@app.route("/")
def home():
    videos = load_videos()
    return render_template("index.html", videos=videos)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("video")
    title = request.form.get("title", "").strip()

    if file and file.filename != "" and title:
        # Kullanıcının verdiği ad doğrudan kullanılırsa uploads/ dışına yazılabilir
        filename = secure_filename(file.filename)
        if not filename:
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
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
