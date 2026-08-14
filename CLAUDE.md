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
database.py      Standalone SQLite bootstrap script — NOT imported by app.py.
videos.json      The live datastore (a JSON array of video objects).
videos.db        SQLite file created by database.py. Currently unused.
uploads/         Uploaded video files, served at /uploads/<filename>.
templates/
  index.html     Home: upload form + video list. Styles are inline in <style>.
  watch.html     Player page: video, like button (fetch/JSON), comments.
static/
  style.css      Legacy stylesheet. NOT linked from either template.
```

Two things to know before you "fix" something that looks broken:

- **`database.py` and `videos.db` are dead code.** `app.py` never imports
  sqlite3 and never touches `videos.db`. The SQLite table (`videos` with
  `id/title/filename/views/likes`) is a half-started migration that was never
  wired up. Don't assume it is the source of truth. If asked to migrate to
  SQLite, that's a real task — say so and do it deliberately, don't do it as a
  side effect of another change.
- **`static/style.css` is not loaded.** Both templates carry their own inline
  `<style>` block. Editing `style.css` changes nothing visible. To restyle a
  page, edit the `<style>` block in that template.

## Data model

`videos.json` is a flat array; there is no index or ID. Everything is looked up
by linear scan on `filename`, which is therefore the de facto primary key.

```json
{
  "title": "string",
  "filename": "string",        // also the file name inside uploads/
  "views": 0,
  "likes": 0,
  "liked_by": ["<ip>"],        // request.remote_addr strings
  "comments": [
    { "text": "string", "ip": "<ip>", "time": "DD.MM.YYYY HH:MM" }
  ]
}
```

Persistence is whole-file: `load_videos()` reads and parses the entire file,
`save_videos()` rewrites it. Every mutating request does a full read-modify-
write. There is no locking, so concurrent writes can lose data — acceptable at
this scale, but don't build anything on top of it that assumes atomicity.

**Backfill pattern:** older records may lack `likes`, `liked_by`, or
`comments`. `watch()`, `like()`, and `comment()` each defensively insert the
missing keys before use. If you add a new field to the video object, add the
same `if "field" not in video` backfill to every route that reads it, or
records written before your change will raise `KeyError`.

**Identity is the client IP** (`request.remote_addr`). It gates like toggling
and is stored on each comment (never rendered — `watch.html` shows only `time`
and `text`). Keep it unrendered. Behind a reverse proxy every user collapses to
one IP, so likes would be shared; that is a known limitation of the current
design, not a bug to patch silently.

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

Validation is minimal and silent. `/upload` requires a file, a non-empty
filename, a non-empty title, and an extension in `ALLOWED_EXTENSIONS`; if any
is missing or the extension is rejected it redirects to `/` with no error
message. `/comment` drops empty comments the same way. That silence is existing
behavior — if you add error reporting, it's a visible product change, so
mention it.

**Upload naming.** `build_safe_filename()` is the only place a stored filename
is produced. It runs `secure_filename` (kills `../` traversal), enforces the
extension allowlist, and appends a short uuid so same-named uploads can't
overwrite each other. Never write `file.filename` to disk directly — always go
through this helper. The extension allowlist is a security control, not a
convenience: `uploads/` is served from the app's own origin, so an uploaded
`.html` or `.svg` would execute as same-origin script.

## Running it

There is no `requirements.txt`, no lockfile, and no virtualenv checked in.
Flask is the only dependency:

```bash
pip install flask
python app.py          # http://127.0.0.1:5000, debug off
```

Runtime knobs, all via environment variables:

| Var | Default | Meaning |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. Only widen to `0.0.0.0` deliberately. |
| `PORT` | `5000` | Port |
| `FLASK_DEBUG` | `0` | `1` enables the Werkzeug debugger — localhost only, never with a public `HOST` |
| `MAX_UPLOAD_MB` | `256` | Upload size cap; exceeding it returns 413 |

`app.py` creates `uploads/` and an empty `videos.json` at import time if they
don't exist, so a fresh clone runs without setup.

There are **no tests, no linter config, and no CI**. Verify changes by running
the server and exercising the flow (upload → watch → like → comment) and by
checking that `videos.json` still parses. If you add tests or a
`requirements.txt`, that's a net improvement — just call it out as an addition
rather than folding it into an unrelated diff.

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
- Existing comments in `app.py` are Turkish. Follow the surrounding language
  when adding comments; the codebase is sparsely commented, so don't add many.

## Security invariants

These are handled — don't regress them:

- Stored filenames always come from `build_safe_filename()` (sanitized,
  extension-allowlisted, uuid-suffixed).
- Uploads are size-capped via `MAX_CONTENT_LENGTH`, with a 413 handler.
- The server binds to localhost and runs with debug off unless `HOST` /
  `FLASK_DEBUG` say otherwise.
- Every response carries `X-Content-Type-Options: nosniff` (`add_security_headers`).
- Templates rely on Jinja autoescaping for titles and comment text — no `|safe`.
- Commenter IPs are stored but never rendered.

## Known sharp edges

Still open. Fix when the task calls for it — flag, don't silently patch, when
it doesn't:

- **Generated data is committed.** `videos.json`, `videos.db`, and the existing
  file in `uploads/` were committed before `.gitignore` existed, so they stay
  tracked and `.gitignore` won't mask them. Note `videos.json` contains
  commenter IP addresses. To stop tracking them without deleting local data:
  `git rm --cached videos.json videos.db uploads/<file>`. Until then, check
  `git status` before committing so test uploads and view-count churn don't
  land in a diff.
- **Content is not verified to be video** beyond the extension check — no
  container/codec sniffing.
- **No rate limiting** on uploads or comments.
- **IP-based identity** is spoofable via proxies and collapses to one user
  behind a reverse proxy (shared likes). Real accounts are the only real fix.

## Git

Work on the branch you were assigned; never push to `main`. Push with
`git push -u origin <branch>`. Commit messages in this repo are Turkish
(`İlk MiniTube sürümü`); either language is fine going forward, just keep them
descriptive.
