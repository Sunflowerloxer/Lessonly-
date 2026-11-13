# Lessonly + AI generation

```
public/index.html   the app (your original, patched)
server.js           auth + secure AI proxy (holds the API key)
.env.example        configuration template
```

## Run it
```bash
npm install
cp .env.example .env      # fill in ANTHROPIC_API_KEY, TOKEN_SECRET, TEACHER_CODE
export $(grep -v '^#' .env | xargs)   # or use: node --env-file=.env server.js
node server.js            # http://localhost:3000
```
Generate a secret with `openssl rand -hex 32`.

## How the AI works
1. Teacher/student picks a template (multiple choice, true/false, flashcards, matching, order).
2. They type a topic or paste notes in **Topic or study notes** and press **Magic Generate**.
3. The browser sends `{type, prompt, count}` to `/api/generate` with a signed token.
4. The server asks Claude to answer **only through a tool whose JSON schema is the chosen template**,
   so the result always fits the template. It is re-validated server-side and again in the browser.
5. The result fills the editor + live preview. The user reviews/edits, then saves as before.

## Security summary
| Risk | Protection |
|---|---|
| API key theft | Key only in server env var; browser never sees it |
| Unauthorised AI use | Sign-in required; HMAC-signed 8 h tokens; teacher access code (+ optional class code for students) |
| Brute-forcing the teacher code | 10 login attempts / 15 min / IP, constant-time comparison |
| Cost abuse | Per-user hourly quota (teacher 30, student 10), per-IP limit, one request at a time per user, daily global cap |
| Prompt injection | User text wrapped as untrusted `<user_material>`; model can only reply via schema tools; `decline_request` for unsafe topics |
| Malicious/malformed AI output | Server + client validation per template, length caps, HTML stripped, answer indices checked, MCQ options shuffled |
| XSS | All output HTML-escaped (already `esc()`); CSP (`connect-src 'self'`, no objects/frames); share links, localStorage and AI output all pass `sanitizeActivity()` |
| Oversized / tampered share links | 60 KB cap + full validation before play |
| Cross-site calls / clickjacking | Same-origin check on `/api`, `frame-ancestors 'none'`, `no-store`, `no-referrer`, nosniff |
| Log leakage | Prompts and keys are never logged |

## Known limits (be honest with your users)
* Activities, progress and saved items still live in each browser's `localStorage`, so a determined
  user can edit their own copy. Teachers can't see students' progress from other devices. Real
  multi-user tracking needs a database + server-side storage (the login/token layer here is the foundation).
* Share links embed the full activity (including answers) in the URL.
* In-memory rate limits reset when the server restarts; use Redis if you run several instances.
* CSP allows inline scripts because the app is a single file. Moving the `<script>` into `app.js`
  lets you drop `'unsafe-inline'` for scripts.
* Serve over HTTPS in production (and set `TRUST_PROXY=1` behind a proxy).
* Review AI content before sharing: it can contain mistakes.
