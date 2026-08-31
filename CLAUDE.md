# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this is

MiniTube — a minimal YouTube-style video sharing app built with Flask. Users
upload a video with a title, watch it, like it (one like per IP, toggleable),
and leave comments. The whole app is one Flask module with a JSON
file as its datastore. There is no user accounts system and no build step —
visitors are anonymous. The only privileged role is a single moderator who
unlocks delete controls with `ADMIN_KEY`.

The UI language is Turkish (labels, flash-free error strings, code comments).
Keep new user-facing strings in Turkish to match; code identifiers stay English.

## Layout

```
app.py           All routes, all persistence helpers. The entire backend.
test_app.py      Security/privacy test suite (stdlib unittest, no deps).
.github/         Actions workflow: runs the suite on 3.10-3.13.
requirements.txt Flask, the only runtime dependency.
videos.json      The live datastore (a JSON array). Gitignored, not tracked.
uploads/         Uploaded video files, served at /uploads/<filename>.
                 Gitignored except .gitkeep, which keeps the directory.
.secret_key      Generated HMAC/session key. Gitignored, mode 600.
rate_limits.db   Shared rate-limit counters (sqlite3). Gitignored.
templates/
  index.html     Home: upload form + video list. Styles are inline in <style>.
  watch.html     Player page: video, like button (fetch/JSON), comments.
static/
  style.css      Legacy stylesheet. NOT linked from either template.
```

One thing to know before you "fix" something that looks broken:

- **`static/style.css` is not loaded.** Both templates carry their own inline
  `<style>` block. Editing `style.css` changes nothing visible. To restyle a
  page, edit the `<style>` block in that template.

`database.py` and `videos.db` used to sit here as a half-started SQLite
migration that nothing imported. They were removed (the table had no rows).
Storage is `videos.json`. If asked to migrate to SQLite, that's a real task —
say so and do it deliberately, don't do it as a side effect of another change.

## Data model

`videos.json` is a flat array; there is no index or ID. Everything is looked up
by linear scan on `filename`, which is therefore the de facto primary key.

```json
{
  "title": "string",
  "filename": "string",        // also the file name inside uploads/
  "views": 0,
  "likes": 0,
  "liked_by": ["<viewer_id>"], // keyed HMAC of the IP, never the IP itself
  "comments": [
    { "text": "string", "time": "DD.MM.YYYY HH:MM" }
  ]
}
```

Persistence is whole-file: `load_videos()` reads and parses the entire file,
`save_videos()` rewrites it. Every mutating request does a full read-modify-
write. There is no locking, so concurrent writes can lose data — acceptable at
this scale, but don't build anything on top of it that assumes atomicity.

**Backfill pattern:** older records may lack `likes`, `liked_by`, or
`comments`. This is centralized in `normalize_video()`, which `load_videos()`
runs over every record on every read, rewriting the file only if something
changed. If you add a new field to the video object, add its default there —
one place, not per route.

`normalize_video()` also migrates legacy data in place: raw IP strings left in
`liked_by` are hashed, and the old `ip` key is stripped from comments. Leave
that migration in place; it is what keeps old files from reintroducing plain
IPs.

**Identity is a keyed hash of the client IP.** `viewer_id()` returns
`HMAC-SHA256(VIEWER_KEY, ip)` truncated to 32 hex chars, and only that value is
persisted. A plain hash would not be enough — IPv4 is 2^32 values, so an
unkeyed digest is brute-forceable; the key is what makes it irreversible.
Comments store no identifier at all, since nothing ever read one.

**Keys are derived per purpose.** `SECRET_KEY` (env, or the generated
`.secret_key` file) is a root that is never used directly: `derive_key()` makes
`SESSION_KEY` for signing the session cookie and `VIEWER_KEY` for `viewer_id()`.
HMAC is one-way, so leaking one subkey does not expose the other or the root.
Add new purposes with a new label rather than reusing an existing subkey.

`legacy_viewer_id()` reproduces the older scheme, where identity was hashed with
`SECRET_KEY` directly. Stored hashes cannot be recomputed — that is the point of
hashing them — so `watch()` and `like()` accept either form and rewrite to the
new one on the next toggle. Once old likes have aged out, that function and its
two call sites can go.

The root key must stay stable across restarts or existing likes stop matching
their owners.

Behind a reverse proxy, `remote_addr` is the proxy's address and every visitor
collapses to one identity — shared likes, and one rate-limit budget for the
whole site. `TRUSTED_PROXY_COUNT` fixes that by enabling `ProxyFix`, but the
number **must** come from the operator: it is how many proxies actually sit in
front of the app. It cannot be derived at runtime, because the only runtime
source is `X-Forwarded-For` and the client writes that header. Set it too high
and the client picks its own IP — there is a test class demonstrating exactly
that. Default is 0, meaning the header is ignored entirely.

## Routes

| Route | Method | Behavior |
|---|---|---|
| `/` | GET | Renders `index.html` with all videos |
| `/upload` | POST | multipart form (`title`, `video`); sanitizes+uniquifies the name, saves file, appends record, redirects to `/` |
| `/watch/<filename>` | GET | Increments `views`, backfills fields, renders `watch.html`; 404 text `"Video bulunamadı"` |
| `/like/<filename>` | POST | Toggles the caller's IP in `liked_by`; returns JSON `{likes, liked}` |
| `/comment/<filename>` | POST | Form field `comment`; appends and redirects back to the watch page |
| `/uploads/<filename>` | GET | `send_from_directory` from `uploads/` |
| `/admin/login` | POST | Form field `admin_key`; sets the session flag |
| `/admin/logout` | POST | Clears the flag |
| `/admin/delete/<filename>` | POST | Deletes the record and the file |
| `/admin/delete-comment/<filename>/<index>` | POST | Deletes one comment by storage index |

`/like` is the only JSON endpoint — `watch.html` calls it with `fetch()` and
updates the counter in place. Everything else is a classic form POST +
redirect. Preserve that split: don't convert form posts to fetch, or vice
versa, without being asked.

`/upload` requires a file, a non-empty filename, a non-empty title, and an
extension in `ALLOWED_EXTENSIONS`. Rejections now report back: the handler
calls `flash()` and `index.html` renders the messages. `/comment` still drops
empty comments silently. Both user-supplied strings are truncated rather than
rejected: comment text to `MAX_COMMENT_LENGTH` (1000) and the title to
`MAX_TITLE_LENGTH` (200). Truncation applies on the way in only — existing
records with longer titles are left as they are, since silently shortening
stored content is not worth it for a storage concern.

**CSRF.** Every POST route requires a token before the handler runs.
`csrf_token()` puts one token per session in the signed cookie; forms carry it
as a hidden `csrf_token` field and `watch.html` reads it from a
`<meta name="csrf-token">` tag for the `fetch()` on `/like`. A missing or wrong
token is a 403 — JSON on `/like`, plain text elsewhere, matching how the 404s
are split.

**Rate limiting.** Counters are rows in `rate_limits.db`, not a dict in the
process, so multiple workers on one host share a single budget. The check and
the insert run inside `BEGIN IMMEDIATE`; without that write lock two workers
could both read "one under the limit" and both admit a request. Timestamps use
`time.time()` rather than `time.monotonic()` because a monotonic clock's origin
is not comparable between processes. Expired rows are deleted on every call, so
the table cannot grow with every IP an attacker cycles through.

Redis would work too, but it would add a runtime dependency and a service to
operate, and `videos.json` already ties the app to one host — a cross-machine
limiter would solve a problem the datastore cannot survive anyway.

**Moderation.** `ADMIN_KEY` is the whole authorization model. It **fails
closed**: unset means `admin_enabled()` is false, the login form is not
rendered, and every admin route answers 403 — an empty key must never authorize
anyone. A correct key sets `session["is_admin"]`, which is safe to trust because
the cookie is signed; clearing `ADMIN_KEY` also revokes existing sessions.
`/admin/login` is in `RATE_LIMITS` so the key cannot be brute-forced, and the
comparison is `hmac.compare_digest` on bytes.

Deletion is irreversible: `admin_delete` drops the record and the file,
`admin_delete_comment` drops one comment. `remove_upload()` re-checks that the
resolved path is inside `uploads/` even though the name comes from the record —
a hand-edited `videos.json` should not be able to delete elsewhere. Comments
have no id, so they are addressed by storage index; `watch.html` renders them
reversed, so the template computes `length - loop.index0 - 1`. If you change
that loop, re-check the index or the wrong comment gets deleted.

**Upload naming.** `build_safe_filename()` is the only place a stored filename
is produced. It runs `secure_filename` (kills `../` traversal), enforces the
extension allowlist, and appends a short uuid so same-named uploads can't
overwrite each other. Never write `file.filename` to disk directly — always go
through this helper. The extension allowlist is a security control, not a
convenience: `uploads/` is served from the app's own origin, so an uploaded
`.html` or `.svg` would execute as same-origin script.

## Running it

Flask is the only dependency; there is no lockfile and no virtualenv checked in:

```bash
pip install -r requirements.txt
python app.py          # http://127.0.0.1:5000, debug off
```

Runtime knobs, all via environment variables:

| Var | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. Only widen to `0.0.0.0` deliberately. |
| `PORT` | `5000` | Port |
| `FLASK_DEBUG` | `0` | `1` enables the Werkzeug debugger — localhost only, never with a public `HOST` |
| `MAX_UPLOAD_MB` | `256` | Upload size cap; exceeding it returns 413 |
| `SECRET_KEY` | generated | HMAC/session key. Unset means a `.secret_key` file is generated and reused. |
| `RATE_LIMIT_WINDOW` | `3600` | Rate-limit window in seconds, shared by every limit below |
| `RATE_LIMIT_UPLOAD` | `10` | Uploads allowed per client per window |
| `RATE_LIMIT_COMMENT` | `30` | Comments allowed per client per window |
| `RATE_LIMIT_LIKE` | `60` | Like toggles allowed per client per window |
| `RATE_LIMIT_ADMIN_LOGIN` | `5` | Admin key attempts per client per window |
| `ADMIN_KEY` | unset | Moderator key. Unset disables the admin routes entirely. |
| `RATE_LIMIT_DB` | `rate_limits.db` | Where shared counters live. All workers must point at the same path. |
| `TRUSTED_PROXY_COUNT` | `0` | How many trusted proxies sit in front. 0 ignores `X-Forwarded-For`. Never guess this. |

`app.py` creates `uploads/`, an empty `videos.json`, and `.secret_key` at
import time if they don't exist, so a fresh clone runs without setup. None of
the three are tracked: runtime data stays out of git, so view-count churn no
longer lands in diffs. A clone starts with an empty library by design.

### In production

`python app.py` starts Werkzeug's development server — it prints a warning
saying so, and it serves one request at a time. For a real deployment use a WSGI
server. gunicorn is deliberately **not** in `requirements.txt`: it is a
deployment choice, and keeping it out is what lets Flask stay the only runtime
dependency.

```bash
pip install gunicorn
ADMIN_KEY=... gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Things that are easy to get wrong here:

- **All workers must share one working directory.** `videos.json`,
  `uploads/`, `.secret_key` and `rate_limits.db` are all resolved relative to
  the process's cwd. Workers in different directories get separate datastores,
  separate identities, and a rate limit multiplied by the worker count.
- **`HOST`, `PORT` and `FLASK_DEBUG` do nothing under gunicorn.** They are read
  inside the `__main__` block, which only runs for `python app.py`. Binding is
  gunicorn's `-b`, and there is no debugger to enable.
- **One host, not several.** Multiple workers on one machine are fine — the
  rate limiter shares counters through SQLite and was verified with four
  gunicorn workers. Multiple *machines* are not: `videos.json` is a local file
  rewritten whole with no cross-host locking, so two machines would silently
  lose each other's writes. That needs the datastore replaced first.
- **Behind TLS**, set `SESSION_COOKIE_SECURE` in `app.config`. It is off because
  the app defaults to plain HTTP on localhost, where enabling it would stop the
  session cookie — and therefore CSRF — from working at all.
- Set `TRUSTED_PROXY_COUNT` only if a reverse proxy is actually in front, and to
  the real number. See the identity section above for why it cannot be guessed.

The test suite is stdlib only — no runner to install:

```bash
python -m unittest -v          # 128 tests
```

GitHub Actions runs exactly that on every push and pull request against `main`,
across Python 3.10 through 3.13 (`.github/workflows/tests.yml`). All four are
verified locally, so a red matrix entry means a real incompatibility rather than
an untested guess. There is still no linter config.

`test_app.py` re-imports `app.py` inside a throwaway directory per test, so it
never touches the real `videos.json` or `uploads/`. It covers the security and
privacy invariants below. Add to it when you touch upload handling, identity,
or the data migration — those are the parts where a regression is silent.

## Conventions

- Keep all backend code in `app.py` unless the task is explicitly a refactor.
  The file is small and flat on purpose.
- Route handlers follow one shape: `load_videos()` → linear scan for the
  matching `filename` → mutate → `save_videos(videos)` → redirect or JSON.
  Match it.
- Not-found responses are Turkish: `"Video bulunamadı"` (plain text + 404 on
  `/watch`, JSON `{"error": ...}` + 404 on `/like`).
- Templates use Jinja autoescaping — never mark user text `|safe`. Comment text
  and titles are user input.
- Styling stays inline per template. Dark theme: background `#121212`, cards
  `#1e1e1e`, inputs `#2a2a2a`, accent red `#ff0000`, liked-state `#ff4757`,
  muted text `#aaa`.
- Any inline `<style>` or `<script>` needs `nonce="{{ csp_nonce }}"` or CSP
  blocks it. Inline event handlers (`onclick=`) cannot carry a nonce at all —
  bind events inside the nonced script with `addEventListener`. A page that
  suddenly renders unstyled is almost always a missing nonce.
- Existing comments in `app.py` are Turkish. Follow the surrounding language
  when adding comments; the codebase is sparsely commented, so don't add many.

## Security invariants

These are handled — don't regress them:

- Stored filenames always come from `build_safe_filename()` (sanitized,
  extension-allowlisted, uuid-suffixed).
- Uploads are size-capped via `MAX_CONTENT_LENGTH`, with a 413 handler.
- The server binds to localhost and runs with debug off unless `HOST` /
  `FLASK_DEBUG` say otherwise.
- Every response carries `X-Content-Type-Options: nosniff`, a nonce-based
  `Content-Security-Policy`, and `X-Frame-Options: DENY`
  (`add_security_headers`). The CSP deliberately has **no** `'unsafe-inline'`:
  with it, an injected script would run and the policy would be decoration.
  `frame-ancestors 'none'` blocks clickjacking; `X-Frame-Options` is the
  fallback for older browsers.
- Every non-GET request needs a valid CSRF token (`verify_csrf`, a
  `before_request` hook). It fails closed, so a new POST route is protected
  without extra work — but it also means any new form needs the hidden
  `csrf_token` field and any new `fetch()` needs the `X-CSRF-Token` header.
  The session cookie is `SameSite=Lax` as a second layer.
- `/upload`, `/comment` and `/like` are rate limited per client
  (`enforce_rate_limit`), keyed by `viewer_id()` so no raw IP is held even in
  memory. It runs *after* `verify_csrf`, so a forged request cannot burn a
  victim's budget — keep that order. Over the limit is a 429 with
  `Retry-After`. A new POST route is **not** limited until its endpoint name is
  added to `RATE_LIMITS`. Counters live in `rate_limits.db` (stdlib `sqlite3`),
  so every worker sharing the directory shares one budget.
- Templates rely on Jinja autoescaping for titles and comment text — no `|safe`.
- Client IPs are never persisted. Likes store `viewer_id()` (keyed HMAC);
  comments store no identifier. `normalize_video()` scrubs legacy plain IPs on
  load — don't remove it, and don't add `request.remote_addr` to a stored
  record.
- `.secret_key` is mode 600 and gitignored. Never commit it.
- `SECRET_KEY` is a root key only. Sign or hash with a `derive_key()` subkey,
  never with the root itself.
- `ADMIN_KEY` fails closed: unset means no admin routes and no login form. A new
  privileged route must go through `require_admin()`, and its endpoint name
  belongs in `RATE_LIMITS` if it takes a secret.

## Known sharp edges

Still open. Fix when the task calls for it — flag, don't silently patch, when
it doesn't:

- **Content is not verified to be video** beyond the extension check — no
  container/codec sniffing.
- **No total disk quota.** Rate limiting slows disk fill but does not cap it —
  a patient client can still keep uploading within its budget.
- **IP-based identity** is still only an approximation of a person. Behind a
  proxy it needs `TRUSTED_PROXY_COUNT` set correctly; on a shared NAT several
  people look like one. Real accounts are the only real fix.

## Git

Work on the branch you were assigned; never push to `main`. Push with
`git push -u origin <branch>`. Commit messages in this repo are Turkish
(`İlk MiniTube sürümü`); either language is fine going forward, just keep them
descriptive.
