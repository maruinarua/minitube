"""MiniTube güvenlik ve gizlilik testleri.

Çalıştırmak için:  python -m unittest -v
"""

import importlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.abspath(__file__))
TEST_KEY = "sabit-test-anahtari"


class MiniTubeTest(unittest.TestCase):
    """app.py'yi izole bir çalışma dizininde taze olarak yükler."""

    env = {}

    def setUp(self):
        self._cwd = os.getcwd()
        self._env = dict(os.environ)
        # Uygulama dizinini ayrı bir kök altına koyuyoruz; böylece "dizinden
        # kaçma" testi paylaşılan /tmp yerine kendi kökünü kontrol edebiliyor.
        self.root = tempfile.mkdtemp()
        self.tmp = os.path.join(self.root, "app")
        os.makedirs(self.tmp)

        os.environ["MINITUBE_SECRET_KEY"] = TEST_KEY
        os.environ.pop("MINITUBE_DEBUG", None)
        os.environ.pop("MINITUBE_MAX_UPLOAD_MB", None)
        os.environ.update(self.env)

        shutil.copy(os.path.join(REPO, "app.py"), os.path.join(self.tmp, "app.py"))
        shutil.copytree(os.path.join(REPO, "templates"), os.path.join(self.tmp, "templates"))

        os.chdir(self.tmp)
        sys.path.insert(0, self.tmp)
        sys.modules.pop("app", None)
        self.module = importlib.import_module("app")
        self.client = self.module.app.test_client()

    def tearDown(self):
        os.chdir(self._cwd)
        sys.path[:] = [p for p in sys.path if p != self.tmp]
        sys.modules.pop("app", None)
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.root, ignore_errors=True)

    # yardımcılar

    def upload(self, filename, data=b"VIDEO-BYTES", title="Test"):
        return self.client.post(
            "/upload",
            data={"title": title, "video": (io.BytesIO(data), filename)},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def stored(self):
        with open(os.path.join(self.tmp, "videos.json")) as f:
            return json.load(f)

    def uploads_dir(self):
        return sorted(os.listdir(os.path.join(self.tmp, "uploads")))

    def write_videos(self, videos):
        with open(os.path.join(self.tmp, "videos.json"), "w") as f:
            json.dump(videos, f)


class UploadSecurityTests(MiniTubeTest):

    def test_path_traversal_stays_inside_uploads(self):
        self.upload("../../escaped.mp4", data=b"OWNED")
        # uploads/../../escaped.mp4 tam olarak test kökümüze denk geliyor
        escaped = os.path.join(self.root, "escaped.mp4")
        self.assertFalse(os.path.exists(escaped), "yükleme uploads/ dışına yazdı")
        self.assertIn("escaped.mp4", self.uploads_dir())

    def test_absolute_path_stays_inside_uploads(self):
        target = os.path.join(self.root, "pwned.mp4")
        self.upload(target, data=b"OWNED")
        self.assertFalse(os.path.exists(target))
        self.assertEqual(len(self.uploads_dir()), 1)

    def test_duplicate_names_do_not_overwrite(self):
        self.upload("clip.mp4", data=b"AAAA", title="birinci")
        self.upload("clip.mp4", data=b"BBBB", title="ikinci")

        by_title = {v["title"]: v["filename"] for v in self.stored()}
        self.assertNotEqual(by_title["birinci"], by_title["ikinci"])

        base = os.path.join(self.tmp, "uploads")
        with open(os.path.join(base, by_title["birinci"]), "rb") as f:
            self.assertEqual(f.read(), b"AAAA")
        with open(os.path.join(base, by_title["ikinci"]), "rb") as f:
            self.assertEqual(f.read(), b"BBBB")

    def test_unusable_filename_is_rejected(self):
        self.upload("...")
        self.assertEqual(self.stored(), [])

    def test_missing_title_is_rejected(self):
        self.upload("clip.mp4", title="")
        self.assertEqual(self.stored(), [])


class UploadTypeTests(MiniTubeTest):

    def test_dangerous_extensions_are_rejected(self):
        for name in ("evil.exe", "shell.sh", "page.php", "x.html", "notes.txt", "noext"):
            with self.subTest(name=name):
                self.upload(name)
                self.assertEqual(self.stored(), [], f"{name} kabul edildi")
                self.assertEqual(self.uploads_dir(), [], f"{name} diske yazıldı")

    def test_allowed_video_types_are_accepted(self):
        for name in ("a.mp4", "b.webm", "c.mov", "d.m4v", "e.ogv", "f.ogg"):
            with self.subTest(name=name):
                self.upload(name, title=name)
        self.assertEqual(len(self.stored()), 6)

    def test_extension_check_is_case_insensitive(self):
        self.upload("SHOUT.MP4", title="buyuk")
        self.assertEqual(len(self.stored()), 1)


class UploadSizeTests(MiniTubeTest):
    env = {"MINITUBE_MAX_UPLOAD_MB": "1"}

    def test_limit_is_configured(self):
        self.assertEqual(self.module.app.config["MAX_CONTENT_LENGTH"], 1024 * 1024)

    def test_oversized_upload_is_rejected(self):
        response = self.upload("big.mp4", data=b"x" * (2 * 1024 * 1024))
        self.assertEqual(response.status_code, 200)  # 413 yakalanıp ana sayfaya dönülüyor
        self.assertEqual(self.stored(), [])
        self.assertEqual(self.uploads_dir(), [])

    def test_upload_under_limit_succeeds(self):
        self.upload("small.mp4", data=b"x" * 1000)
        self.assertEqual(len(self.stored()), 1)


class PrivacyTests(MiniTubeTest):

    def test_comment_does_not_store_ip(self):
        self.upload("clip.mp4")
        self.client.post("/comment/clip.mp4", data={"comment": "merhaba"})

        comment = self.stored()[0]["comments"][0]
        self.assertNotIn("ip", comment)
        self.assertEqual(set(comment), {"text", "time"})
        self.assertNotIn("127.0.0.1", json.dumps(self.stored()))

    def test_like_stores_hash_not_raw_ip(self):
        self.upload("clip.mp4")
        self.client.post("/like/clip.mp4", environ_base={"REMOTE_ADDR": "203.0.113.9"})

        liked_by = self.stored()[0]["liked_by"]
        self.assertEqual(len(liked_by), 1)
        self.assertNotIn("203.0.113.9", liked_by)
        self.assertTrue(self.module.is_viewer_id(liked_by[0]))

    def test_viewer_id_is_not_a_plain_hash(self):
        # Anahtarsız düz SHA-256 olsaydı IPv4 uzayı kaba kuvvetle çözülürdü
        import hashlib
        plain = hashlib.sha256(b"203.0.113.9").hexdigest()[:32]
        self.assertNotEqual(self.module.viewer_id("203.0.113.9"), plain)

    def test_legacy_raw_ips_are_scrubbed_on_load(self):
        self.write_videos([{
            "title": "eski",
            "filename": "old.mp4",
            "views": 3,
            "likes": 1,
            "liked_by": ["127.0.0.1"],
            "comments": [{"text": "selam", "ip": "127.0.0.1", "time": "01.01.2026 10:00"}],
        }])

        self.client.get("/")

        raw = json.dumps(self.stored())
        self.assertNotIn("127.0.0.1", raw)
        self.assertNotIn('"ip"', raw)
        video = self.stored()[0]
        self.assertTrue(self.module.is_viewer_id(video["liked_by"][0]))
        self.assertEqual(video["likes"], 1)          # sayaç korunuyor
        self.assertEqual(video["comments"][0]["text"], "selam")

    def test_migrated_like_still_toggles(self):
        # Eski düz IP karmaya çevrildikten sonra aynı kullanıcı beğeniyi geri alabilmeli
        self.write_videos([{
            "title": "eski", "filename": "old.mp4", "views": 0, "likes": 1,
            "liked_by": ["127.0.0.1"], "comments": [],
        }])
        response = self.client.post("/like/old.mp4", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.get_json(), {"likes": 0, "liked": False})


class BehaviourTests(MiniTubeTest):

    def test_like_toggles_both_ways(self):
        self.upload("clip.mp4")
        first = self.client.post("/like/clip.mp4").get_json()
        second = self.client.post("/like/clip.mp4").get_json()
        self.assertEqual(first, {"likes": 1, "liked": True})
        self.assertEqual(second, {"likes": 0, "liked": False})

    def test_separate_viewers_like_independently(self):
        self.upload("clip.mp4")
        self.client.post("/like/clip.mp4", environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.client.post("/like/clip.mp4", environ_base={"REMOTE_ADDR": "10.0.0.2"})
        self.assertEqual(self.stored()[0]["likes"], 2)

    def test_watch_counts_views_and_serves_file(self):
        self.upload("clip.mp4", data=b"VID")
        self.assertEqual(self.client.get("/watch/clip.mp4").status_code, 200)
        self.assertEqual(self.stored()[0]["views"], 1)
        served = self.client.get("/uploads/clip.mp4")
        self.assertEqual(served.data, b"VID")
        served.close()

    def test_watch_uses_matching_mimetype(self):
        self.upload("clip.webm")
        page = self.client.get("/watch/clip.webm").get_data(as_text=True)
        self.assertIn('type="video/webm"', page)

    def test_missing_video_returns_404(self):
        self.assertEqual(self.client.get("/watch/yok.mp4").status_code, 404)

    def test_comment_is_capped_and_escaped(self):
        self.upload("clip.mp4")
        self.client.post("/comment/clip.mp4", data={"comment": "a" * 5000})
        self.assertEqual(len(self.stored()[0]["comments"][0]["text"]),
                         self.module.MAX_COMMENT_LENGTH)

        self.client.post("/comment/clip.mp4", data={"comment": "<script>alert(1)</script>"})
        page = self.client.get("/watch/clip.mp4").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_empty_comment_is_ignored(self):
        self.upload("clip.mp4")
        self.client.post("/comment/clip.mp4", data={"comment": "   "})
        self.assertEqual(self.stored()[0]["comments"], [])


class ConfigTests(MiniTubeTest):

    def test_debug_is_off_by_default(self):
        self.assertFalse(self.module.debug_enabled())

    def test_debug_is_opt_in(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            os.environ["MINITUBE_DEBUG"] = value
            self.assertTrue(self.module.debug_enabled(), value)
        for value in ("", "0", "false", "no"):
            os.environ["MINITUBE_DEBUG"] = value
            self.assertFalse(self.module.debug_enabled(), value)

    def test_secret_key_persists_across_restarts(self):
        os.environ.pop("MINITUBE_SECRET_KEY", None)
        sys.modules.pop("app", None)
        first = importlib.import_module("app")
        generated = first.SECRET_KEY

        sys.modules.pop("app", None)
        second = importlib.import_module("app")
        self.assertEqual(generated, second.SECRET_KEY)

    def test_secret_file_is_not_world_readable(self):
        os.environ.pop("MINITUBE_SECRET_KEY", None)
        sys.modules.pop("app", None)
        importlib.import_module("app")
        mode = os.stat(os.path.join(self.tmp, ".secret_key")).st_mode
        self.assertEqual(mode & 0o077, 0, "anahtar dosyası başkalarına açık")


if __name__ == "__main__":
    unittest.main(verbosity=2)
