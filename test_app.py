"""MiniTube güvenlik ve gizlilik testleri.

Çalıştırmak için:  python -m unittest -v
"""

import contextlib
import importlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest


@contextlib.contextmanager
def quiet_app_errors(app):
    """Kasıtlı 500 üreten testlerde Flask'ın traceback logunu susturur."""
    previous = app.logger.disabled
    app.logger.disabled = True
    try:
        yield
    finally:
        app.logger.disabled = previous

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

        os.environ["SECRET_KEY"] = TEST_KEY
        os.environ.pop("FLASK_DEBUG", None)
        os.environ.pop("MAX_UPLOAD_MB", None)
        os.environ.update(self.env)

        shutil.copy(os.path.join(REPO, "app.py"), os.path.join(self.tmp, "app.py"))
        shutil.copytree(os.path.join(REPO, "templates"), os.path.join(self.tmp, "templates"))

        os.chdir(self.tmp)
        sys.path.insert(0, self.tmp)
        sys.modules.pop("app", None)
        self.module = importlib.import_module("app")
        self.client = self.module.app.test_client()
        # Token'ı bir kez alıp saklıyoruz: her POST'tan önce GET yapmak
        # bozuk-veri testlerinde ana sayfayı da patlatırdı.
        self.token = self.fetch_csrf_token()

    def tearDown(self):
        os.chdir(self._cwd)
        sys.path[:] = [p for p in sys.path if p != self.tmp]
        sys.modules.pop("app", None)
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.root, ignore_errors=True)

    # yardımcılar

    def fetch_csrf_token(self, client=None):
        """Ana sayfayı çekip formdaki gizli token alanını okur."""
        client = client or self.client
        page = client.get("/").get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', page)
        if match is None:
            raise AssertionError("ana sayfada csrf_token alanı bulunamadı")
        return match.group(1)

    def post_form(self, path, data=None, **kwargs):
        """Form POST'u; CSRF anahtarını otomatik ekler."""
        payload = dict(data or {})
        payload.setdefault("csrf_token", self.token)
        return self.client.post(path, data=payload, **kwargs)

    def post_json(self, path, **kwargs):
        """JSON uçlarına POST; anahtarı başlıkla gönderir."""
        headers = dict(kwargs.pop("headers", {}))
        headers.setdefault("X-CSRF-Token", self.token)
        return self.client.post(path, headers=headers, **kwargs)

    def upload(self, filename, data=b"VIDEO-BYTES", title="Test"):
        return self.client.post(
            "/upload",
            data={
                "title": title,
                "video": (io.BytesIO(data), filename),
                "csrf_token": self.token,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def upload_video(self, filename="clip.mp4", data=b"VIDEO-BYTES", title="Test"):
        """Yükler ve diske yazılan gerçek adı döndürür (uuid eki nedeniyle)."""
        self.upload(filename, data=data, title=title)
        return self.stored()[-1]["filename"]

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

        saved = self.uploads_dir()
        self.assertEqual(len(saved), 1)
        # build_safe_filename uuid eki koyuyor: escaped-<hex>.mp4
        self.assertTrue(saved[0].startswith("escaped-"), saved[0])
        self.assertTrue(saved[0].endswith(".mp4"), saved[0])

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
    env = {"MAX_UPLOAD_MB": "1"}

    def test_limit_is_configured(self):
        self.assertEqual(self.module.app.config["MAX_CONTENT_LENGTH"], 1024 * 1024)

    def test_oversized_upload_is_rejected(self):
        response = self.upload("big.mp4", data=b"x" * (2 * 1024 * 1024))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.stored(), [])
        self.assertEqual(self.uploads_dir(), [])

    def test_upload_under_limit_succeeds(self):
        self.upload("small.mp4", data=b"x" * 1000)
        self.assertEqual(len(self.stored()), 1)


class UploadFaultToleranceTests(MiniTubeTest):
    """Yükleme sırasında bir şey ters giderse arkada çöp kalmamalı."""

    def test_very_long_filename_is_accepted(self):
        # Eskiden NAME_MAX aşıldığı için file.save() OSError verip 500 dönüyordu
        response = self.upload("a" * 300 + ".mp4", title="uzun")
        self.assertEqual(response.status_code, 200)

        records = self.stored()
        self.assertEqual(len(records), 1)
        name = records[0]["filename"]
        self.assertLessEqual(len(name), self.module.MAX_FILENAME_LENGTH)
        self.assertTrue(name.endswith(".mp4"))
        self.assertEqual(self.uploads_dir(), [name])

    def test_generated_names_never_exceed_filesystem_limit(self):
        for length in (1, 100, 250, 300, 1000):
            with self.subTest(length=length):
                name = self.module.build_safe_filename("b" * length + ".mp4")
                self.assertLessEqual(len(name), self.module.MAX_FILENAME_LENGTH)
                self.assertTrue(name.endswith(".mp4"))

    def test_short_names_are_not_truncated(self):
        name = self.module.build_safe_filename("tatil.mp4")
        self.assertTrue(name.startswith("tatil-"), name)

    def test_failed_record_write_leaves_no_orphan_file(self):
        def out_of_space(videos):
            raise OSError(28, "No space left on device")

        original = self.module.save_videos
        self.module.save_videos = out_of_space
        try:
            with quiet_app_errors(self.module.app):
                self.upload("kayip.mp4")
        finally:
            self.module.save_videos = original

        self.assertEqual(self.uploads_dir(), [], "kayıt yazılamadı ama dosya diskte kaldı")
        self.assertEqual(self.stored(), [])

    def test_corrupt_datastore_leaves_no_orphan_file(self):
        with open(os.path.join(self.tmp, "videos.json"), "w") as f:
            f.write("{bozuk")

        with quiet_app_errors(self.module.app):
            self.upload("kayip.mp4")
        self.assertEqual(self.uploads_dir(), [], "kayıt okunamadı ama dosya diskte kaldı")

    def test_successful_upload_is_unaffected(self):
        name = self.upload_video("normal.mp4", data=b"VID")
        self.assertEqual(len(self.stored()), 1)
        self.assertEqual(self.uploads_dir(), [name])
        with open(os.path.join(self.tmp, "uploads", name), "rb") as f:
            self.assertEqual(f.read(), b"VID")


class UploadValidationTests(MiniTubeTest):
    """Mevcut doğrulama davranışını sabitler; değiştirmez."""

    def test_missing_file_field_is_rejected_without_error(self):
        response = self.client.post(
            "/upload",
            data={"title": "T", "csrf_token": self.token},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.stored(), [])

    def test_whitespace_only_title_is_rejected(self):
        self.upload("clip.mp4", title="   ")
        self.assertEqual(self.stored(), [])

    def test_extension_only_filename_is_rejected(self):
        self.upload(".mp4")
        self.assertEqual(self.stored(), [])

    def test_double_extension_stores_only_the_allowed_extension(self):
        name = self.upload_video("evil.php.mp4")
        self.assertEqual(os.path.splitext(name)[1], ".mp4")

    def test_null_byte_in_filename_is_stripped(self):
        name = self.upload_video("a\x00b.mp4")
        self.assertNotIn("\x00", name)

    def test_record_filename_matches_file_on_disk(self):
        name = self.upload_video("tutarli.mp4")
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "uploads", name)))

    def test_empty_file_is_currently_accepted(self):
        # Bilinen boşluk: içerik doğrulanmıyor, 0 baytlık dosya kabul ediliyor.
        # Sessizce değişmesin diye sabitliyoruz.
        name = self.upload_video("bos.mp4", data=b"")
        self.assertEqual(len(self.stored()), 1)
        self.assertEqual(os.path.getsize(os.path.join(self.tmp, "uploads", name)), 0)

    def test_upload_requires_no_authentication(self):
        # Yetkilendirme katmanı yok: kimlik bilgisi taşımayan istemci de
        # yükleyebiliyor. Tasarım kararı, ama testte görünür olsun.
        anonymous = self.module.app.test_client()
        token = self.fetch_csrf_token(anonymous)
        anonymous.post(
            "/upload",
            data={
                "title": "anon",
                "video": (io.BytesIO(b"VID"), "anon.mp4"),
                "csrf_token": token,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(len(self.stored()), 1)


class CsrfTests(MiniTubeTest):
    """Durum değiştiren uçlar geçerli token olmadan çalışmamalı."""

    def prepare_video(self):
        return self.upload_video("clip.mp4")

    # --- token yoksa reddedilmeli ---

    def test_upload_without_token_is_rejected(self):
        response = self.client.post(
            "/upload",
            data={"title": "T", "video": (io.BytesIO(b"VID"), "clip.mp4")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored(), [])
        self.assertEqual(self.uploads_dir(), [])

    def test_comment_without_token_is_rejected(self):
        name = self.prepare_video()
        response = self.client.post(f"/comment/{name}", data={"comment": "sızdı"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored()[0]["comments"], [])

    def test_like_without_token_is_rejected_as_json(self):
        name = self.prepare_video()
        response = self.client.post(f"/like/{name}")
        self.assertEqual(response.status_code, 403)
        self.assertIn("error", response.get_json())
        self.assertEqual(self.stored()[0]["likes"], 0)

    # --- yanlış token da reddedilmeli ---

    def test_wrong_token_is_rejected(self):
        name = self.prepare_video()
        response = self.client.post(
            f"/comment/{name}", data={"comment": "x", "csrf_token": "yanlis-anahtar"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored()[0]["comments"], [])

    def test_token_from_another_session_is_rejected(self):
        name = self.prepare_video()
        other = self.module.app.test_client()
        other_token = self.fetch_csrf_token(other)
        self.assertNotEqual(other_token, self.token)

        response = self.client.post(
            f"/comment/{name}", data={"comment": "x", "csrf_token": other_token}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored()[0]["comments"], [])

    def test_non_ascii_token_is_rejected_without_crashing(self):
        # compare_digest str ile ASCII dışı girdide TypeError atar; 500 değil
        # 403 dönmeli.
        name = self.prepare_video()
        response = self.client.post(
            f"/comment/{name}", data={"comment": "x", "csrf_token": "çünkü-ünlü"}
        )
        self.assertEqual(response.status_code, 403)

    def test_cross_origin_post_without_token_is_rejected(self):
        # Denetimde bu tam olarak çalışıyordu: yabancı Origin ile beğeni
        name = self.prepare_video()
        response = self.client.post(
            f"/like/{name}", headers={"Origin": "https://kotu-site.example"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.stored()[0]["likes"], 0)

    # --- geçerli token ile normal akış ---

    def test_valid_token_allows_all_state_changes(self):
        name = self.prepare_video()
        self.assertEqual(self.post_json(f"/like/{name}").status_code, 200)
        self.assertEqual(self.post_form(f"/comment/{name}", data={"comment": "selam"}).status_code, 302)

        record = self.stored()[0]
        self.assertEqual(record["likes"], 1)
        self.assertEqual(record["comments"][0]["text"], "selam")

    def test_get_requests_are_unaffected(self):
        name = self.prepare_video()
        for path in ("/", f"/watch/{name}", f"/uploads/{name}"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    # --- token sayfalara gömülüyor mu ---

    def test_forms_carry_the_token(self):
        name = self.prepare_video()
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn('name="csrf_token"', home)

        watch = self.client.get(f"/watch/{name}").get_data(as_text=True)
        self.assertIn('name="csrf_token"', watch)
        self.assertIn('name="csrf-token"', watch)      # fetch için meta etiketi

    def test_token_is_not_embedded_in_javascript_string(self):
        # Meta etiketinden okunuyor; JS bağlamına gömülmüyor
        name = self.prepare_video()
        watch = self.client.get(f"/watch/{name}").get_data(as_text=True)
        # Etiket artık nonce özniteliği taşıyor; içeriği öznitelikten
        # bağımsız çıkarıyoruz
        match = re.search(r"<script[^>]*>(.*?)</script>", watch, re.S)
        self.assertIsNotNone(match, "watch sayfasında script bloğu yok")
        script = match.group(1)
        self.assertNotIn(self.token, script)
        self.assertIn("X-CSRF-Token", script)

    def test_session_cookie_is_samesite_lax(self):
        self.assertEqual(self.module.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        response = self.client.get("/")
        cookies = response.headers.getlist("Set-Cookie")
        if cookies:
            self.assertTrue(any("SameSite=Lax" in c for c in cookies), cookies)


class RateLimitTests(MiniTubeTest):
    """Kimliksiz istemci sınırsız yazma yapamamalı."""

    env = {
        "RATE_LIMIT_UPLOAD": "2",
        "RATE_LIMIT_COMMENT": "2",
        "RATE_LIMIT_LIKE": "2",
        "RATE_LIMIT_WINDOW": "60",
    }

    def freeze_clock(self, start=1000.0):
        """_now'ı teste bağlar; ilerletmek için dönen sözlüğü kullan."""
        clock = {"t": start}
        self.module._now = lambda: clock["t"]
        return clock

    def seed_video(self, filename="seed.mp4"):
        """Yükleme kotasını harcamadan kayıt oluşturur."""
        self.write_videos([{
            "title": "seed", "filename": filename, "views": 0,
            "likes": 0, "liked_by": [], "comments": [],
        }])
        with open(os.path.join(self.tmp, "uploads", filename), "wb") as f:
            f.write(b"VID")
        return filename

    # --- sınırlar uygulanıyor mu ---

    def test_upload_limit_is_enforced(self):
        self.assertEqual(self.upload("a.mp4", title="1").status_code, 200)
        self.assertEqual(self.upload("b.mp4", title="2").status_code, 200)

        blocked = self.upload("c.mp4", title="3")
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(len(self.stored()), 2, "sınır aşıldığı halde kayıt yazıldı")
        self.assertEqual(len(self.uploads_dir()), 2, "sınır aşıldığı halde dosya yazıldı")

    def test_comment_limit_is_enforced(self):
        name = self.seed_video()
        for i in range(2):
            self.assertEqual(
                self.post_form(f"/comment/{name}", data={"comment": f"y{i}"}).status_code, 302
            )

        blocked = self.post_form(f"/comment/{name}", data={"comment": "fazla"})
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(len(self.stored()[0]["comments"]), 2)

    def test_like_limit_is_reported_as_json(self):
        name = self.seed_video()
        for _ in range(2):
            self.assertEqual(self.post_json(f"/like/{name}").status_code, 200)

        blocked = self.post_json(f"/like/{name}")
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("error", blocked.get_json())

    def test_retry_after_header_is_sent(self):
        name = self.seed_video()
        for _ in range(2):
            self.post_json(f"/like/{name}")

        blocked = self.post_json(f"/like/{name}")
        retry_after = int(blocked.headers["Retry-After"])
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 60)

    # --- neyin sayılıp sayılmadığı ---

    def test_each_viewer_has_its_own_budget(self):
        name = self.seed_video()
        for _ in range(2):
            self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.assertEqual(
            self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code,
            429,
        )
        # Başka bir istemci etkilenmemeli
        self.assertEqual(
            self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.0.2"}).status_code,
            200,
        )

    def test_get_requests_are_not_limited(self):
        name = self.seed_video()
        for _ in range(10):
            self.assertEqual(self.client.get("/").status_code, 200)
            self.assertEqual(self.client.get(f"/watch/{name}").status_code, 200)

    def test_rejected_uploads_still_count(self):
        # Geçersiz yükleme spam'i sınırı atlatmamalı
        self.upload("evil.exe", title="1")
        self.upload("evil.exe", title="2")
        self.assertEqual(self.stored(), [])

        self.assertEqual(self.upload("gecerli.mp4", title="3").status_code, 429)

    def test_csrf_rejected_requests_do_not_consume_budget(self):
        # Sahte istek kurbanın kotasını yakmamalı: kancaların sırası önemli
        name = self.seed_video()
        for _ in range(5):
            self.assertEqual(self.client.post(f"/like/{name}").status_code, 403)

        self.assertEqual(self.post_json(f"/like/{name}").status_code, 200)

    # --- pencere ve bellek ---

    def test_budget_refills_after_window(self):
        name = self.seed_video()
        clock = self.freeze_clock()

        for _ in range(2):
            self.post_json(f"/like/{name}")
        self.assertEqual(self.post_json(f"/like/{name}").status_code, 429)

        clock["t"] += 61          # pencere doldu
        self.assertEqual(self.post_json(f"/like/{name}").status_code, 200)

    def test_expired_entries_are_pruned(self):
        # Süpürme olmasa sözlük her yeni IP için kalıcı kayıt biriktirirdi
        name = self.seed_video()
        clock = self.freeze_clock()

        for octet in range(20):
            self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": f"10.0.1.{octet}"})
        self.assertGreaterEqual(len(self.module._rate_hits), 20)

        clock["t"] += 60 + 300 + 1     # pencere + süpürme aralığı
        self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.2.1"})

        self.assertLess(len(self.module._rate_hits), 5, "eski kayıtlar süpürülmedi")


class SecurityHeaderTests(MiniTubeTest):
    """CSP ve çerçeveleme korumaları."""

    def policy(self, path="/"):
        response = self.client.get(path)
        header = response.headers.get("Content-Security-Policy", "")
        response.close()
        return header

    def directive(self, name, path="/"):
        for part in self.policy(path).split(";"):
            part = part.strip()
            if part.split(" ")[0] == name:
                return part
        return None

    def test_csp_is_sent_on_every_response(self):
        name = self.upload_video("clip.mp4")
        for path in ("/", f"/watch/{name}", f"/uploads/{name}"):
            with self.subTest(path=path):
                self.assertTrue(self.policy(path), f"{path} için CSP yok")

    def test_framing_is_denied(self):
        self.assertEqual(self.directive("frame-ancestors"), "frame-ancestors 'none'")
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

    def test_scripts_and_styles_use_a_nonce_not_unsafe_inline(self):
        # 'unsafe-inline' olsaydı enjekte edilen script de çalışırdı ve
        # CSP'nin XSS'e karşı bir anlamı kalmazdı
        for name in ("script-src", "style-src"):
            with self.subTest(directive=name):
                value = self.directive(name)
                self.assertIn("'nonce-", value)
                self.assertNotIn("unsafe-inline", value)
                self.assertNotIn("unsafe-eval", value)

    def test_header_nonce_matches_the_rendered_page(self):
        response = self.client.get("/")
        body = response.get_data(as_text=True)
        header = response.headers["Content-Security-Policy"]

        rendered = re.search(r'<style nonce="([^"]+)"', body)
        self.assertIsNotNone(rendered, "şablonda nonce yok")
        self.assertIn(f"'nonce-{rendered.group(1)}'", header,
                      "başlıktaki nonce sayfadakiyle uyuşmuyor")

    def test_nonce_changes_between_requests(self):
        first = re.search(r"'nonce-([^']+)'", self.policy()).group(1)
        second = re.search(r"'nonce-([^']+)'", self.policy()).group(1)
        self.assertNotEqual(first, second, "nonce sabit - tahmin edilebilir olurdu")

    def test_templates_have_no_inline_event_handlers(self):
        # Satır içi handler nonce alamaz, CSP tarafından bloklanır
        name = self.upload_video("clip.mp4")
        for path in ("/", f"/watch/{name}"):
            with self.subTest(path=path):
                body = self.client.get(path).get_data(as_text=True)
                for attribute in ("onclick=", "onload=", "onerror=", "onsubmit="):
                    self.assertNotIn(attribute, body)

    def test_dangerous_sources_are_locked_down(self):
        self.assertEqual(self.directive("object-src"), "object-src 'none'")
        self.assertEqual(self.directive("base-uri"), "base-uri 'none'")
        self.assertEqual(self.directive("default-src"), "default-src 'self'")

    def test_video_and_fetch_sources_are_allowed(self):
        # Politika kendi işlevselliğimizi kırmamalı
        self.assertEqual(self.directive("media-src"), "media-src 'self'")
        self.assertEqual(self.directive("connect-src"), "connect-src 'self'")
        self.assertEqual(self.directive("form-action"), "form-action 'self'")


class PrivacyTests(MiniTubeTest):

    def test_comment_does_not_store_ip(self):
        name = self.upload_video()
        self.post_form(f"/comment/{name}", data={"comment": "merhaba"})

        comment = self.stored()[0]["comments"][0]
        self.assertNotIn("ip", comment)
        self.assertEqual(set(comment), {"text", "time"})
        self.assertNotIn("127.0.0.1", json.dumps(self.stored()))

    def test_like_stores_hash_not_raw_ip(self):
        name = self.upload_video()
        self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "203.0.113.9"})

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
        response = self.post_json("/like/old.mp4", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.get_json(), {"likes": 0, "liked": False})


class BehaviourTests(MiniTubeTest):

    def test_like_toggles_both_ways(self):
        name = self.upload_video()
        first = self.post_json(f"/like/{name}").get_json()
        second = self.post_json(f"/like/{name}").get_json()
        self.assertEqual(first, {"likes": 1, "liked": True})
        self.assertEqual(second, {"likes": 0, "liked": False})

    def test_separate_viewers_like_independently(self):
        name = self.upload_video()
        self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.post_json(f"/like/{name}", environ_base={"REMOTE_ADDR": "10.0.0.2"})
        self.assertEqual(self.stored()[0]["likes"], 2)

    def test_watch_counts_views_and_serves_file(self):
        name = self.upload_video(data=b"VID")
        self.assertEqual(self.client.get(f"/watch/{name}").status_code, 200)
        self.assertEqual(self.stored()[0]["views"], 1)
        served = self.client.get(f"/uploads/{name}")
        self.assertEqual(served.data, b"VID")
        served.close()

    def test_watch_uses_matching_mimetype(self):
        name = self.upload_video("clip.webm")
        page = self.client.get(f"/watch/{name}").get_data(as_text=True)
        self.assertIn('type="video/webm"', page)

    def test_missing_video_returns_404(self):
        self.assertEqual(self.client.get("/watch/yok.mp4").status_code, 404)

    def test_nosniff_header_on_every_response(self):
        name = self.upload_video(data=b"VID")
        for path in ("/", f"/watch/{name}", f"/uploads/{name}"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                response.close()

    def test_comment_is_capped_and_escaped(self):
        name = self.upload_video()
        self.post_form(f"/comment/{name}", data={"comment": "a" * 5000})
        self.assertEqual(len(self.stored()[0]["comments"][0]["text"]),
                         self.module.MAX_COMMENT_LENGTH)

        self.post_form(f"/comment/{name}", data={"comment": "<script>alert(1)</script>"})
        page = self.client.get(f"/watch/{name}").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_empty_comment_is_ignored(self):
        name = self.upload_video()
        self.post_form(f"/comment/{name}", data={"comment": "   "})
        self.assertEqual(self.stored()[0]["comments"], [])


class PersistenceTests(MiniTubeTest):
    """save_videos atomik olmalı: yarım dosya asla görünmemeli."""

    def sample(self, count=200):
        return [{"title": f"v{i}", "filename": f"v{i}.mp4", "views": i,
                 "likes": 0, "liked_by": [], "comments": []} for i in range(count)]

    def db_path(self):
        return os.path.join(self.tmp, "videos.json")

    def temp_leftovers(self):
        return [n for n in os.listdir(self.tmp) if n.startswith(".videos-")]

    def test_save_writes_expected_content(self):
        self.module.save_videos(self.sample(3))
        self.assertEqual(len(self.stored()), 3)
        self.assertEqual(self.stored()[1]["filename"], "v1.mp4")

    def test_crash_during_save_leaves_previous_file_intact(self):
        self.module.save_videos(self.sample(3))
        before = self.stored()

        real_dump = json.dump

        def dying_dump(obj, fp, **kwargs):
            fp.write('[\n  {\n    "title": "yar')   # yarım yazıp ölüyor
            raise KeyboardInterrupt("süreç öldü")

        json.dump = dying_dump
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.module.save_videos(self.sample(9))
        finally:
            json.dump = real_dump

        # Eski dosya hâlâ tam ve okunabilir olmalı
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.temp_leftovers(), [], "yarım geçici dosya kaldı")

    def test_no_temp_files_left_after_success(self):
        for _ in range(3):
            self.module.save_videos(self.sample(2))
        self.assertEqual(self.temp_leftovers(), [])

    def test_concurrent_reads_never_see_partial_file(self):
        import threading
        import time

        videos = self.sample(200)
        self.module.save_videos(videos)

        failures = []
        stop = threading.Event()

        def writer():
            while not stop.is_set():
                self.module.save_videos(videos)

        def reader():
            while not stop.is_set():
                try:
                    self.module.load_videos()
                except Exception as exc:      # JSONDecodeError dahil
                    failures.append(repr(exc))

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for t in threads:
            t.start()
        time.sleep(0.7)
        stop.set()
        for t in threads:
            t.join()

        self.assertEqual(failures[:3], [], f"{len(failures)} okuma yarım dosya gördü")

    def test_existing_file_mode_is_preserved(self):
        os.chmod(self.db_path(), 0o640)
        self.module.save_videos(self.sample(1))
        self.assertEqual(os.stat(self.db_path()).st_mode & 0o777, 0o640)


class ConfigTests(MiniTubeTest):

    def test_debug_is_off_by_default(self):
        self.assertFalse(self.module.debug_enabled())

    def test_debug_is_opt_in(self):
        # CLAUDE.md'de belgelenen sözleşme tam olarak FLASK_DEBUG=1
        os.environ["FLASK_DEBUG"] = "1"
        self.assertTrue(self.module.debug_enabled())
        for value in ("", "0", "true", "yes"):
            os.environ["FLASK_DEBUG"] = value
            self.assertFalse(self.module.debug_enabled(), value)

    def test_secret_key_persists_across_restarts(self):
        os.environ.pop("SECRET_KEY", None)
        sys.modules.pop("app", None)
        first = importlib.import_module("app")
        generated = first.SECRET_KEY

        sys.modules.pop("app", None)
        second = importlib.import_module("app")
        self.assertEqual(generated, second.SECRET_KEY)

    def test_secret_file_is_not_world_readable(self):
        os.environ.pop("SECRET_KEY", None)
        sys.modules.pop("app", None)
        importlib.import_module("app")
        mode = os.stat(os.path.join(self.tmp, ".secret_key")).st_mode
        self.assertEqual(mode & 0o077, 0, "anahtar dosyası başkalarına açık")


if __name__ == "__main__":
    unittest.main(verbosity=2)
