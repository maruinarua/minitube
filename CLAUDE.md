# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this is

MiniTube — a minimal YouTube-style video sharing app built with Flask. Users
upload a video with a title, watch it, like it (one like per IP, toggleable),
and leave comments. The whole app is a single-process Flask server with a JSON
file as its datastore. There is no user accounts system, no auth, and no build
step.

The UI language is Turkish (labels, flash-free error strings, code comments).
Keep new user-facing strings in Turkish to match; code identifiers stay English.

## Layout

```
app.py           All routes, all persistence helpers. The entire backend.
test_app.py      Security/privacy test suite (stdlib unittest, no deps).
requirements.txt Flask, the only runtime dependency.
videos.json      The live datastore (a JSON array of video objects).
uploads/         Uploaded video files, served at /uploads/<filename>.
.secret_key      Generated HMAC/session key. Gitignored, mode 600.
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
`HMAC-SHA256(SECRET_KEY, ip)` truncated to 32 hex chars, and only that value is
persisted. A plain hash would not be enough — IPv4 is 2^32 values, so an
unkeyed digest is brute-forceable; the key is what makes it irreversible.
Comments store no identifier at all, since nothing ever read one.

The key comes from `SECRET_KEY`, falling back to a generated `.secret_key`
file. It must stay stable across restarts or existing likes stop matching their
owners. Behind a reverse proxy every user still collapses to one address, so
likes would be shared; that is a known limitation of the design, not a bug to
patch silently.

## Routes

| Route | Method | Behavior |
|---|---|---|
| `/` | GET | Renders `index.html` with all videos |
| `/upload` | POST | multipart form (`title`, `video`); sanitizes+uniquifies the name, saves file, appends record, redirects to `/` |
| `/watch/<filename>` | GET | Increments `views`, backfills fields, renders `watch.html`; 404 text `"Video bulunamadı"` |
| `/like/<filename>` | POST | Toggles the caller's IP in `liked_by`; returns JSON `{likes, liked}` |
| `/comment/<filename>` | POST | Form field `comment`; appends and redirects back to the watch page |
| `/uploads/<filename>` | GET | `send_from_directory` from `uploads/` |

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

**CSRF.** All three POST routes require a token before the handler runs.
`csrf_token()` puts one token per session in the signed cookie; forms carry it
as a hidden `csrf_token` field and `watch.html` reads it from a
`<meta name="csrf-token">` tag for the `fetch()` on `/like`. A missing or wrong
token is a 403 — JSON on `/like`, plain text elsewhere, matching how the 404s
are split.

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
| `RATE_LIMIT_WINDOW` | `3600` | Rate-limit window in seconds, shared by all three limits |
| `RATE_LIMIT_UPLOAD` | `10` | Uploads allowed per client per window |
| `RATE_LIMIT_COMMENT` | `30` | Comments allowed per client per window |
| `RATE_LIMIT_LIKE` | `60` | Like toggles allowed per client per window |

`app.py` creates `uploads/`, an empty `videos.json`, and `.secret_key` at
import time if they don't exist, so a fresh clone runs without setup.

There is a test suite and no linter config or CI:

```bash
python -m unittest -v          # 85 tests, stdlib only
```

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
  added to `RATE_LIMITS`.
- Templates rely on Jinja autoescaping for titles and comment text — no `|safe`.
- Client IPs are never persisted. Likes store `viewer_id()` (keyed HMAC);
  comments store no identifier. `normalize_video()` scrubs legacy plain IPs on
  load — don't remove it, and don't add `request.remote_addr` to a stored
  record.
- `.secret_key` is mode 600 and gitignored. Never commit it.

## Known sharp edges

Still open. Fix when the task calls for it — flag, don't silently patch, when
it doesn't:

- **Generated data is committed.** `videos.json` and the existing file in
  `uploads/` were committed before `.gitignore` existed, so they stay tracked
  and `.gitignore` won't mask them. They no longer contain IP addresses, but
  view-count churn still lands in diffs. To stop tracking them without deleting
  local data: `git rm --cached videos.json uploads/<file>`. Until then, check
  `git status` before committing.
- **Content is not verified to be video** beyond the extension check — no
  container/codec sniffing.
- **Rate limiting is per process and in memory.** `_rate_hits` lives in the
  process, so running multiple workers gives each its own counters and a
  restart clears them. Fine for this single-process app; a shared store would
  be needed behind a load balancer.
- **No total disk quota.** Rate limiting slows disk fill but does not cap it —
  a patient client can still keep uploading within its budget.
- **IP-based identity** is spoofable via proxies and collapses to one user
  behind a reverse proxy (shared likes). Real accounts are the only real fix.

## Git

Work on the branch you were assigned; never push to `main`. Push with
`git push -u origin <branch>`. Commit messages in this repo are Turkish
(`İlk MiniTube sürümü`); either language is fine going forward, just keep them
descriptive.
