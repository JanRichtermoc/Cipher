# Runbook — staging VPS from bare image to deployed relay

The executable half of **P5.S05**. `INFRASTRUCTURE.md` records *which* host and *why*; this
records *what is done to it*, in an order chosen so that no step can lock the operator out of
the machine or expose the box between steps.

Written to be re-run: **P9.S01 buys a production VPS and must meet the same bar.** A hardening
pass that exists only as a memory of what was typed once cannot be met a second time.

Read with [`INFRASTRUCTURE.md`](INFRASTRUCTURE.md) (access, the emailed password, the host-move
constraint), [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7, and [`BACKEND.md`](BACKEND.md) §9.

**Ubuntu 24.04 LTS.** Differences on 22.04 are noted where they change a command.

## State of the staging box

Executed 2026-07-29 against the OVH VPS. Every "Done when" below was observed, not assumed.

| Stage | | Notes |
|---|---|---|
| A | done | Key-only login. The first keypair was discarded — its passphrase was lost — and `authorized_keys` held three copies of it; it now holds exactly one live key. |
| B | done | Confirmed the cloud-init trap on this image: `50-cloud-init.conf` set `PasswordAuthentication yes` and beat `60-cloudimg-settings.conf`'s `no`. The `10-` drop-in wins over both, and `ssh_pwauth: false` stops cloud-init re-asserting it at boot. Negative-tested: the server's refusal changed from `(publickey,password)` to `(publickey)`. |
| C | done | 22/80/443, v4 and v6. |
| D | done | Reboot window 04:30 UTC; box set to UTC. |
| E | done | Needed `backend = systemd` — this image ships no rsyslog, so the stock jail would have run and banned nothing. Verified four ways: jail listed, filter matched 26 real journal lines, live jail counted 3 induced failures, ban reached the packet filter and unban removed it. |
| F | done | Docker 29.6.2, Compose v5.3.1, log rotation on, `no-new-privileges` global. |
| G | done | All three containers healthy, 8080 on loopback only. Secrets generated on the box. Deployed revision was `9a279a4`; now `3f4cf92` — see H.0b. |
| G.1 | done 2026-08-06 | AUDIT 5.28. `docker-compose.yml` confines Postgres and Redis the way `api` already was and bounds all three, but the routine deploy recreates only `api`, so the datastores kept the configuration they were created with. Pre-state observed: `postgres`/`redis` both `CapDrop=[] Memory=0 PidsLimit=<nil>`, `api` `CapDrop=[ALL]` with no limits. Ran `git pull --ff-only` then `docker compose up -d --build`. **Rehearsed first**, because the untested path was an *existing* data directory rather than a fresh volume: locally, a volume initialised under the pre-5.28 file was switched to the hardened one, Postgres returned healthy and a marker row survived. Post-state on the box: all three `CapDrop=[ALL]`, `no-new-privileges:true`, `api`/`redis` read-only, `Mem=512M/1G/256M`, `Pids=256/512/128`; Redis `maxmemory 201326592`, `noeviction`, `appendonly no`, empty `save`. `/health` and `/health/ready` both 200, 8080 still loopback-only, both datastores `PortBindings {}`, 0 ERROR lines, `schema up to date applied=0`, no unset-pepper warning on a build that emits one. |
| **Deployed revision** | current as of 2026-08-11 | Now `6e6bbf2` — **zero commits behind `main`**, deployed 2026-08-11 for AUDIT 5.39 and 5.40; see that row. Before it, `1e04d7c` as of 2026-08-08, deployed for P7.S03 (migration `0002`); see that row. Before it, `7df7e79` as of 2026-08-07. Deployed 2026-08-07 a second time that day to ship AUDIT 5.33, the access-log route; before that it was `64b06b3` for AUDIT 5.32, the prekey-publication body limit, when the box had been on `421ee6f`, seven commits behind, of which exactly one touched `server/` (`6091307`). Before that it was `3f4cf92` (PR #22), 64 commits behind, of which **five touched `server/`** and were therefore missing from the running relay: `72105ea` (AUDIT 5.25, atomic invite redemption), `dd48a9c`, `f134de3` (AUDIT 5.27, seven handler and store bounds), `2c28da9` (AUDIT 5.29, the nginx files) and `23a0d29` (AUDIT 5.28) — all shipped together with G.1. **This drift is the recurring failure here** — H.0b caught it on 2026-07-30 four commits behind, G.1 caught it again on 2026-08-06, and 5.32 is the first time it cost a *field* session rather than an audit row: the fix existed and passed CI while the relay a real iPhone was talking to did not have it. It is structural rather than anyone's mistake: deploys are per-finding, the box is touched only when a finding names it, and nothing in the repository can see the gap because no gate reaches the host. Re-check with `git rev-list --count HEAD..origin/main` before trusting any finding's status against this box. |
| 5.32 deploy | done 2026-08-07 | AUDIT 5.32. The clone is `--depth 1`, so the routine `git pull --ff-only` has no common ancestor to fast-forward from; used `git fetch --depth 1 origin main` then `git checkout -B main FETCH_HEAD`, which is safe here only because the tree was clean and `server/.env` is untracked — both checked first, along with 34 GB free. Diff previewed before switching: five files, all `server/`, all `6091307`. Then `docker compose up -d --build`. OBSERVED after: only `api` recreated (`postgres`/`redis` kept running, as G.1 documents); all three healthy; `/health` and `/health/ready` both 200 on the box; `/health/ready` 200 over TLS from the internet; `ss` shows `127.0.0.1:8080` only; port 8080 from the Mac times out; `verify-pins.sh` still matches the served leaf, its non-zero exit being the known backup-key gap (6.14). |
| 5.33 deploy | done 2026-08-07 | AUDIT 5.33, the access log naming no route for anything arriving through Nginx. One `server/` commit (`a333af6`); same shallow-clone procedure as the 5.32 deploy row, diff previewed before switching (five files, all `server/`). **Verified by observation rather than by the absence of errors,** because the defect was invisible in exactly the way a health check cannot see: a matched route driven through Nginx from the Mac now logs `"route":"GET /v1/keys/{aci}"` with status 401, where an hour earlier the same shape logged `(unmatched)`. The two properties that had to survive the fix were checked at the same time — a request to an unregistered path still logs the `(unmatched)` placeholder rather than echoing the attacker-chosen path, and the populated path never appears: the probe's UUID occurs **0 times** in the log. Also confirmed after: all three containers healthy, `/health` and `/health/ready` 200 locally and 200 over TLS, `ss` showing `127.0.0.1:8080` only, port 8080 from the Mac timing out, and `verify-pins.sh` still matching the served leaf with its known backup-key gap (6.14). |
| P7.S03 deploy | done 2026-08-08 | Migration `0002`, narrowing `push_tokens.token_nonce` from 24 bytes to 12 (AES-GCM). One `server/` commit in the window (`9df9b82`); the box had been on `7df7e79`, **zero commits behind for `server/`**, which is the first time that has been true at deploy time here. Same shallow-clone procedure as the 5.32 row — tree clean and `server/.env` untracked were both checked first, 33 GB free — and the diff was previewed before switching: eleven files, all `server/`. Only `api` was recreated; `postgres` and `redis` kept running, as G.1 documents. **The migration's central safety claim was verified on the box rather than assumed:** `push_tokens` held **0 rows** before the deploy, so narrowing a CHECK could not fail against existing data — and it still holds 0 after. OBSERVED, in order: `schema up to date applied=1` naming `migrations/0002_push_token_nonce.sql`; the constraint reading `octet_length(token_nonce) = 24` before and `= 12` after; both migrations listed in `schema_migrations`; **0** ERROR lines; all three containers healthy; `/health` and `/health/ready` 200 on the box and 200 over TLS from the Mac (HTTP/2, certificate verified); `ss` showing `127.0.0.1:8080` with 80/443 public; port 8080 unreachable from the Mac. Then `api` was restarted once deliberately, to prove idempotence: `applied=0`. `verify-pins.sh` still matches the served leaf and still exits non-zero on the known backup-key gap (6.14). **`RELAY_PUSH_TOKEN_KEY` was deliberately not set** — `grep -c` on the variable *name* returns 0 — because push does not exist until P8 and a relay with no key refuses to store a token rather than storing one in the clear. Setting it belongs with P8.S02, alongside the endpoint that first writes a token. Database credentials were never read: every query ran as `docker exec … sh -c` referencing the container's own `$POSTGRES_PASSWORD`, so the value never left the container. |
| 5.39 + 5.40 deploy | done 2026-08-11 | AUDIT 5.39 (per-recipient pending-byte ceiling) and 5.40 (per-account prekey-pool ceiling). **Three `server/` commits in the window**, not two: `650932a` carried AUDIT 6.24's `RELAY_PUSH_TOKEN_KEY` compose wiring and had never been deployed, which is the drift the row above describes, found by running `git rev-list --count HEAD..origin/main -- server/` before touching anything. The box had been on `1e04d7c`, 38 commits behind. No migration: 5.39 and 5.40 add none, and `0001_init.sql` differs only in **comments** — inert here because `store.Migrate` skips a file whose name is already in `schema_migrations` and deliberately keeps no checksums of applied files. OBSERVED: `schema up to date applied=0 migrations=null`; `listening` on `:8080`; image built `2026-08-11T13:00:56Z`; only `api` recreated, `postgres` and `redis` untouched at 4 days' uptime; `/health` 200 on the box. Both new ceilings run at their defaults — `grep -c` on the two variable *names* returns **2** in `docker-compose.yml` and **0** in `.env` — and the same name-only count inside the running container returns 2, which is the AUDIT 6.24 invariant verified against the process rather than the file. **`RELAY_PUSH_TOKEN_KEY` is still unset**, so push-token writes still refuse rather than storing a token in the clear. No value of any variable was read. **Two operator traps this deploy exposed, both worth knowing before the next one.** *First*, the initial `docker compose up -d --build api` was interrupted mid `go build` and produced no image, and every check still looked fine: the container reported `Up 2 days (healthy)` and `/health` returned `{"status":"ok"}` — because the **old** binary was healthy. Uptime and image age are what say whether a deploy landed; health says only that something is serving. *Second*, the documented abandon-the-deploy command (`git checkout <previous>`) was run **41 seconds after** the rebuilt image already existed, so it moved the checkout and not the running service: the relay ran the new code while the working tree sat detached on the old revision with a `docker-compose.yml` missing both new variables — a state in which a later restart would have silently rolled the relay back *and* dropped the env forwarding. `git reflog` established the ordering and `git checkout main` repaired it without touching the container, which stayed up. An abandon command is only valid **before** a successful build. |
| H.0b | done 2026-07-30 | `RELAY_RATELIMIT_PEPPER` set, after the deploy that first contains it. The box had been on `9a279a4` and was **four relay-affecting commits behind** — it did not have 5.22 (blob byte quota never checked), 5.23 (ack and blob-delete unmetered) or the Go 1.25.12 stdlib fixes. Fast-forwarded to `3f4cf92`, rebuilt, then the pepper. OBSERVED, in this order: `/health` 200 over the wire on the new build with the old `.env`; the unset-pepper warning appearing for the first time (**0 → 1**, because the build that emits it had not been deployed before); then **1 → 0** after the value was set. See the trap noted in H.0b — the pre-deploy 0 was not a pass. |
| H.0 | done | `RELAY_TRUSTED_PROXY=172.18.0.1/32` — the bridge **gateway**, not the subnet. Verified live both ways: rotating `X-Real-IP` through the host's published port gets fresh buckets, the same rotation from inside the `postgres` container still hits `429`. |
| H.1–H.5 | done | `relay.mgchatman.app`, Let's Encrypt ECDSA leaf expiring 2026-10-27, `reuse_key = True` confirmed in the renewal config. TLS **1.3 only** — and see AUDIT 5.16, because it was 1.2-accepting at first while the config read as 1.3-only, and the first probe reported a false pass. Verified end to end from the internet: forging `X-Real-IP` per request does **not** escape the rate limit (8 requests, one bucket, throttled at the 6th). Access log carries no request URI. |
| H.6 | done 2026-08-06 | AUDIT 5.29. Found already applied and verified independently the same day; **who ran it is not recorded here because it was not observed** — the files were installed at 09:34 UTC+2, before the G.1 pull that first brought `server/deploy/nginx/` onto the box, so they came from elsewhere (GitHub, scp) rather than from the checkout. Both files byte-identical to `server/deploy/nginx/`; three `access_log` directives (`off` for the redirect and the catch-all, `minimal` for the relay); `/var/log/nginx/` holds two empty files and **no rotated generations**, where seven were present with `access.log.1` at 102 KB before. Proved live, not inferred: traffic to the port-80 redirect and to the bare-IP catch-all left the stock `access.log` at **0 bytes**, while the relay's own `/var/log/cipher/cipher-access.log` grew — the positive control, without which an unchanged stock log is also what a box serving nothing looks like. A minimal line carries client IP, method, status, bytes and duration, and no path, user agent or referrer. The redirect answers `Server: nginx` with no version. |
| I | done | Post-H full scan: **22, 80, 443 open; everything else filtered**, both families. Pre-H the same scan showed 65532 filtered / 2 closed / 1 open, confirming 80 and 443 only became reachable when Nginx was deployed. |

---

## 0. Before the first command

**Ownership.** Stages A–G need shell access and are the operator's to run, or Claude's once the
`cipher-staging` alias resolves. Stage H additionally needs the DNS record in §H.1, which only the
operator can create with the current registrar access. ACME registration intentionally uses no
email (§H.3). §H.0 is the one part of H that needs neither — do it first.

**Never paste into a chat transcript:** the OVH password, the contents of `~/.ssh/cipher_staging`,
`server/.env`, or any TLS private key. The IP and hostname are public the moment DNS resolves and
are fine to discuss. (`INFRASTRUCTURE.md` § Access.)

**Recovery path.** Every step below can be undone from the **OVH KVM console** in the control
panel, which does not go through SSH. Find it before you need it: VPS → `...` → *Console*. It is
the answer to "I locked myself out", including a fail2ban self-ban.

**Keep two sessions.** From Stage B onward, keep the terminal you are working in open and prove
each change from a *second, new* connection. A broken sshd config discovered while you still have
a live session is a one-line fix; discovered after you disconnect it is a console session.

---

## Stage A — get in, and prove the key before changing anything

The account is only as good as the key. Nothing is hardened until this stage passes, because
every later step assumes the key works.

1. Copy the VPS IPv4 (and IPv6, if present) from the OVH panel.
2. Install the public key. **`ssh-copy-id`, not by hand** — it creates `~/.ssh`, sets 700/600,
   and appends without clobbering, which is three chances to get it wrong manually:

   ```sh
   ssh-copy-id -o PubkeyAuthentication=no -i ~/.ssh/cipher_staging.pub ubuntu@<IP>
   ```

   `PubkeyAuthentication=no` skips straight to password auth, which is all this needs; without
   it, a passphrased key prompts for the passphrase before failing anyway. Expect
   `Number of key(s) added: 1`.

   **A key added in the OVH panel *after* provisioning does nothing** — the panel injects keys at
   install time only. If the panel is the route, it has to happen at (re)install.

   Afterwards, confirm `authorized_keys` holds only keys you control. Repeated attempts leave
   duplicates, and a discarded key left in the file is a live credential nobody holds:

   ```sh
   ssh -i ~/.ssh/cipher_staging ubuntu@<IP> 'ssh-keygen -lf ~/.ssh/authorized_keys'
   ```

3. **Prove key-only login from the Mac, in a new terminal:**

   ```sh
   ssh -i ~/.ssh/cipher_staging -o PasswordAuthentication=no ubuntu@<IP> 'echo KEY OK'
   ```

   Anything other than `KEY OK` — stop. Do not proceed to Stage B. The whole ordering argument
   in `INFRASTRUCTURE.md` rests on this having passed.

4. Add the alias to `~/.ssh/config` on the Mac (`INFRASTRUCTURE.md` § Access), then confirm
   `ssh cipher-staging 'echo ALIAS OK'`.

**Done when:** `ssh cipher-staging` logs in with no password prompt.

---

## Stage B — SSH lockdown

First, because OVH emails the initial password in plaintext and applies no default-deny firewall.
That password is live on a public host until this stage completes.

### B.1 The trap that makes most of these tutorials wrong

Ubuntu's `/etc/ssh/sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`, and **sshd
takes the first value it obtains for a keyword, not the last**. Cloud images ship
`/etc/ssh/sshd_config.d/50-cloud-init.conf` containing `PasswordAuthentication yes`. Editing the
main file therefore changes nothing: the include has already answered the question.

The drop-in below is named `10-` so it sorts *before* `50-cloud-init.conf` and wins.

```sh
sudo tee /etc/ssh/sshd_config.d/10-cipher-hardening.conf >/dev/null <<'EOF'
# P5.S05. Sorts before 50-cloud-init.conf deliberately: sshd takes the FIRST
# value obtained for a keyword, and cloud-init re-enables password auth.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
# Change this if the image's default user is not `ubuntu` — an AllowUsers that
# names nobody is a lockout, recoverable only from the OVH console.
AllowUsers ubuntu
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
AllowAgentForwarding no
# `local` keeps `ssh -L` working — the safe way to reach the loopback-bound API
# before TLS exists — while refusing remote forwards, which turn a session into
# an inbound listener.
AllowTcpForwarding local
EOF
sudo chmod 644 /etc/ssh/sshd_config.d/10-cipher-hardening.conf
```

`KbdInteractiveAuthentication no` is not redundant. `PasswordAuthentication no` alone leaves
PAM's keyboard-interactive path, which prompts for a password and accepts one.

### B.2 Validate, then apply

```sh
sudo sshd -t && echo "SYNTAX OK"          # never restart without this
sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication|authenticationmethods|allowusers)'
```

`sshd -T` prints the **effective** configuration after all includes. Read it, do not assume it —
this is the check that catches B.1. Expect `passwordauthentication no`.

```sh
sudo systemctl restart ssh
```

This does not drop live sessions, on either init model. 24.04 socket-activates
OpenSSH (`ssh.socket` spawning `ssh@.service` per connection), so each new connection re-reads
the config regardless; the restart is belt and braces.

### B.3 Negative test (required)

A gate that has not been shown to fail is not a gate. From the Mac, keeping the working session
open:

```sh
# 1. The key still works.
ssh cipher-staging 'echo STILL IN'

# 2. Password auth is refused — must fail with "Permission denied (publickey)".
ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password \
    -o BatchMode=no ubuntu@<IP> 'echo SHOULD NOT PRINT'

# 3. Root is refused.
ssh -i ~/.ssh/cipher_staging root@<IP> 'echo SHOULD NOT PRINT'
```

Test 2 printing a password prompt at all means B.1 bit you. Go back.

**Done when:** `sshd -T` reports `passwordauthentication no` **and** test 2 is refused without
prompting.

---

## Stage C — firewall

```sh
sudo apt-get update
sudo apt-get install -y ufw
```

**Allow 22 before enabling.** `ufw enable` applies `default deny incoming` immediately; enabling
first and allowing second drops your own session mid-command.

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   comment 'ssh'
sudo ufw allow 80/tcp   comment 'acme http-01 + redirect'
sudo ufw allow 443/tcp  comment 'relay api'
sudo ufw --force enable
sudo ufw status verbose
```

**IPv6.** OVH assigns one. Confirm `IPV6=yes` in `/etc/default/ufw` (the default on 24.04) —
otherwise every rule above protects v4 only while the box answers on v6. If you change it,
`sudo ufw reload`. The port scan in Stage I checks both families for exactly this reason.

**Docker bypasses UFW.** Docker writes its own `nat`/`FORWARD` rules, so a container published
with `-p 8080:8080` is reachable from the internet *even with UFW denying 8080*. The relay's
`docker-compose.yml` publishes `127.0.0.1:8080:8080`, which is why this is safe here — and why
`Scripts/verify-relay.sh` fails if that binding ever loses its loopback prefix. Do not add a
`ports:` entry to any other service.

**Done when:** `ufw status verbose` shows deny-incoming plus exactly 22/80/443, v4 and v6.

---

## Stage D — patching

```sh
sudo apt-get install -y unattended-upgrades apt-listchanges
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
sudo tee /etc/apt/apt.conf.d/52unattended-upgrades-cipher >/dev/null <<'EOF'
// Reboot for kernel updates. The relay's containers are restart: unless-stopped
// and Postgres recovers cleanly, so an unattended reboot is cheaper than running
// a known-vulnerable kernel until someone remembers.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF
```

Verify it actually resolves something rather than merely being installed:

```sh
sudo unattended-upgrade --dry-run --debug 2>&1 | tail -20
sudo systemctl status unattended-upgrades --no-pager
```

Set the clock to UTC so logs and Postgres timestamps agree with everything else:

```sh
sudo timedatectl set-timezone UTC
```

**No swap.** 4 GB is ample for Go + Postgres + Redis, and a swapfile writes process memory —
database credentials, decrypted session tokens in flight — to a disk that OVH also snapshots. The
absence is deliberate; do not "helpfully" add one.

---

## Stage E — fail2ban

```sh
sudo apt-get install -y fail2ban
sudo tee /etc/fail2ban/jail.d/cipher.local >/dev/null <<'EOF'
[DEFAULT]
# systemd, not the default log backend: 24.04 cloud images may ship without
# rsyslog, so /var/log/auth.log does not exist and the sshd jail fails to start.
# The failure is quiet — fail2ban runs, and bans nothing, forever.
backend  = systemd
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
# aggressive also matches pre-auth disconnects. On a key-only host there is no
# "Failed password" line to match, so normal mode would see nothing to ban.
mode    = aggressive
EOF
sudo systemctl enable --now fail2ban
sudo systemctl restart fail2ban
```

Verify — both halves:

```sh
sudo fail2ban-client status                # sshd must be in the jail list
sudo fail2ban-client status sshd           # "Filter" + "Actions", no error
journalctl -u fail2ban -n 30 --no-pager    # no "Have not found any log file"
```

**Self-ban recovery:** the OVH console, then `sudo fail2ban-client set sshd unbanip <ip>`. This
is the reason `bantime` is one hour rather than permanent.

---

## Stage F — Docker

Docker's own repository, not `docker.io` from Ubuntu: the Compose v2 plugin the relay's tooling
assumes is only packaged there.

```sh
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
                        docker-buildx-plugin docker-compose-plugin
```

Daemon configuration:

```sh
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true
}
EOF
sudo systemctl restart docker
```

Log rotation is not housekeeping. Container stdout is an unbounded, unrotated metadata store by
default: it fills the disk, and until it does it retains exactly the request-shaped records
`BACKEND.md` §4 and the P4.S11 logging audit exist to avoid keeping.

```sh
sudo usermod -aG docker "$USER"     # then log out and back in
```

**The `docker` group is root-equivalent** — a member can bind-mount `/` into a container. It is
accepted here because the only member is the sole operator, who already has `sudo`. It is not a
privilege boundary and must not be described as one. The *workload* is non-root independently:
`server/Dockerfile` runs `USER 65532:65532` on `scratch`, with `cap_drop: [ALL]` and
`read_only: true` in compose.

**Done when:** `docker run --rm hello-world` succeeds without `sudo`.

---

## Stage G — deploy the relay on loopback

Still no external exposure: the API binds `127.0.0.1:8080`. This validates the build on the real
box before TLS is in the picture.

```sh
sudo apt-get install -y git
git clone --depth 1 https://github.com/JanRichtermoc/Cipher.git ~/cipher
cd ~/cipher/server
```

Public repo, no credentials. `vendor/` is committed, so the image build needs no network for Go
modules — the property `server/README.md` calls out.

**Generate secrets on the server. They exist nowhere else — not in the repo, not in a chat.**

```sh
umask 077
cp .env.example .env
pg_pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
redis_pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg_pw}|" .env
sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${redis_pw}|" .env
unset pg_pw redis_pw
chmod 600 .env
grep -c '^[A-Z_]*=.\+' .env      # 6 — every variable populated
```

That generator is the one `.env.example` prescribes, verbatim. Hex, not base64, because
`POSTGRES_PASSWORD` is interpolated into a `postgres://` URL where `/`, `+` and `=` corrupt the
connection string — and `head` is the producer rather than the consumer because the idiom
everyone reaches for, `tr -dc … </dev/urandom | head -c 32`, is a SIGPIPE trap that works on a
Mac and fails on Linux. Read the comment block in `.env.example` before changing either.

```sh
docker compose up -d --build
docker compose ps                       # all three healthy
curl -sS http://127.0.0.1:8080/health
curl -sS -i http://127.0.0.1:8080/health/ready
```

Prove it is *not* reachable from anywhere else:

```sh
ss -tlnp | grep 8080                    # 127.0.0.1:8080 only — never 0.0.0.0
```

```sh
# From the Mac. Must time out or refuse.
nc -vz -w 5 <IP> 8080
```

**Done when:** `/health/ready` returns 200 on the box and port 8080 is unreachable from the Mac.

### G.1 Applying the datastore confinement to a box deployed before AUDIT 5.28

A box deployed before that finding runs Postgres and Redis with Docker's default capability set and
no ceiling on memory, CPU or process count. The fix is in `docker-compose.yml`, so it is already in
the repository after a `git pull` — but **the routine deploy does not apply it**. Every deploy step
in this runbook ends `docker compose up -d --build api`, which recreates one container; the other
two keep running with the configuration they were created with, and `docker compose ps` reports
them healthy either way. Nothing here is wrong until you check.

Confirm the box is actually affected before changing anything:

```sh
ssh cipher-staging 'cd ~/cipher/server && docker inspect $(docker compose ps -q postgres) \
  --format "CapDrop={{.HostConfig.CapDrop}} Memory={{.HostConfig.Memory}} PidsLimit={{.HostConfig.PidsLimit}}"'
```

`CapDrop=[]` with no limits means unconfined — the state this closes. **Read the limit fields
loosely:** an unset `PidsLimit` renders as `0` on some Docker versions and `<nil>` on others
(observed `<nil>`, Docker 29.6.2, 2026-08-06), because the daemon reports the pointer rather than
the value. Either means absent. If it already reads `CapDrop=[ALL]` with numeric limits, stop:
there is nothing to do.

**Precondition, and it is the one that makes this step worth anything: the change must be on the
branch the box tracks.** `git pull --ff-only` here pulls `main`, so running this while the fix is
still in an unmerged pull request recreates all three containers against the *old* compose file —
no confinement applied, and every rate-limit bucket emptied for nothing. Check before pulling,
rather than inferring it from the pull succeeding:

```sh
git ls-remote origin refs/heads/main
ssh cipher-staging 'cd ~/cipher && git fetch -q origin && \
  git show origin/main:server/docker-compose.yml | grep -cE "^[[:space:]]*cap_drop:"'   # 3, not 1
```

One `cap_drop:` directive is the pre-5.28 file, which confines `api` alone. Three is the file this
step exists to deploy.

**Anchored to the start of the line, and that is not style.** The bare `grep -c cap_drop` this
check was first written with returns **4** on the current file: the header comment explains the
control using the word it is searching for, so the count includes the prose describing the setting
as though it were the setting. Observed 2026-08-06, and it is AUDIT 6.7 and **R3** exactly — the
same defect `Scripts/verify-relay.sh` was negative-tested into fixing, reappearing in a runbook
command written in the same change. An operator reading `4` against a documented `3` stops and
looks for a problem that is not there; worse, the loose form would count a file whose directives had
all been deleted but whose comments survived.

Then pull and recreate **all three** services, not just `api`:

```sh
cd ~/cipher && git pull --ff-only
cd server && docker compose up -d --build
docker compose ps                       # all three healthy
```

**On a box that is several revisions behind, this deploys far more than the confinement.** `--build`
rebuilds the relay image from whatever the pull brought with it, so every intervening server change
ships in the same step. Read `git log --oneline HEAD@{1}..HEAD -- server/` immediately afterwards
and record what actually went out, because "applied the confinement" is then an incomplete
description of what happened — and if the relay misbehaves after this, the confinement is not the
first thing to suspect.

`up -d` recreates a container whose configuration changed and leaves the named volumes alone, so
`postgres-data` survives. Do not add `-v`: that deletes the volumes, which on this box means every
account, every published prekey and every undelivered message.

Verify against the runtime rather than the file — the file is what `Scripts/verify-relay.sh` already
checks, and the question here is what the daemon actually applied:

```sh
for s in api postgres redis; do
  printf '%s: ' "$s"
  docker inspect $(docker compose ps -q $s) --format \
    'CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}} PidsLimit={{.HostConfig.PidsLimit}}'
done
```

Every line must show `CapDrop=[ALL]`, `no-new-privileges:true`, and non-zero `Memory` and
`PidsLimit`. Then confirm Redis took its own ceiling, which is the half that protects the rate
limits from the OOM killer:

```sh
docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning \
  config get maxmemory maxmemory-policy'     # 201326592, noeviction
```

Finally, the service itself:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://relay.mgchatman.app/health   # expect 200
```

**Expect a short interruption, and one side effect.** Recreating Postgres and Redis restarts them,
so requests in flight fail for a few seconds. Redis has no persistence, so **every rate-limit bucket
is emptied** — the same reset `RELAY_RATELIMIT_PEPPER` cannot prevent, since the pepper keys the
buckets rather than storing them. That is acceptable for a planned recreation and is precisely the
event `--maxmemory` exists to stop happening unplanned.

**Rollback.** The previous compose file is in Git, so a container that refuses to start is recovered
by checking out the older revision of that one file and running `docker compose up -d` again:

```sh
cd ~/cipher && git show HEAD~1:server/docker-compose.yml > /tmp/compose.prev.yml
cd server && docker compose -f /tmp/compose.prev.yml up -d
```

The data volumes are untouched by either direction, so this is reversible without data loss. If
Postgres fails to start under the reduced capability set, capture the reason before rolling back —
`docker compose logs postgres --since 5m` — and send it back rather than widening `cap_add` on the
box, because a capability added on the host is one the gate cannot see.

---

## Stage H — DNS, Nginx, TLS

### H.0 Configure the trust boundary — do this before Nginx, not after

Putting Nginx in front means every request reaches the relay from the proxy. `clientAddr()` feeds
that to the rate limiter, and `POST /v1/invite/redeem` is the only per-IP limit there is — so
without configuration all callers share one bucket and **the first caller to spend the 5/hour
budget denies invite redemption to everyone**. `httpx.RealIP` (P5.S05) fixes this, but only when
told which peer is the proxy. `BACKEND.md` §9.2 has the full reasoning.

**The obvious value is wrong.** `ports: "127.0.0.1:8080:8080"` puts `docker-proxy` in the path,
and it opens a *fresh* connection into the container from the compose bridge **gateway**. The
relay therefore never sees `127.0.0.1` — so a config naming loopback trusts nothing while looking
configured. Read the real value off the running network, and use it as a `/32`:

```sh
cd ~/cipher/server
GW=$(docker network inspect cipher-relay_internal \
       --format '{{ (index .IPAM.Config 0).Gateway }}')
echo "$GW"
if grep -q '^RELAY_TRUSTED_PROXY=' .env; then
  sed -i "s|^RELAY_TRUSTED_PROXY=.*|RELAY_TRUSTED_PROXY=${GW}/32|" .env
else
  printf 'RELAY_TRUSTED_PROXY=%s/32\n' "$GW" >> .env
fi
docker compose up -d
```

**The gateway, not the subnet.** Proxied requests only ever arrive from the gateway, so a `/16`
is wider than needed — and the extra width is `postgres` and `redis`, at `.2` and `.3`. Under a
subnet a compromised datastore container could name any client address it liked; under the `/32`
it cannot. Prove it, from inside a container that is *not* the gateway:

```sh
# Rotates X-Real-IP every request. If the header were believed this would never
# be throttled; it must still reach 429.
for i in $(seq 1 7); do
  docker exec cipher-relay-postgres-1 wget -q -O /dev/null -S \
    --header="Content-Type: application/json" \
    --header="X-Real-IP: 192.0.2.$i" \
    --post-data='{"code":"aaaaaaaaaaaaaaaaaaaaaaaaaa","identity_key":"","registration_id":1}' \
    http://api:8080/v1/invite/redeem 2>&1 | grep -oE 'HTTP/1.1 [0-9]+'
done
```

Verify the relay actually took it, rather than assuming:

```sh
docker compose exec api true 2>/dev/null || \
  docker inspect cipher-relay-api-1 --format '{{range .Config.Env}}{{println .}}{{end}}' \
    | grep RELAY_TRUSTED_PROXY
```

Empty is a valid setting and means *trust nobody* — the pre-P5 behaviour. It fails toward
over-throttling, never toward no limit, which is why it is the default.

#### H.0b Set the rate-limit pepper — do this at the next deploy

**Outstanding on this box.** Without `RELAY_RATELIMIT_PEPPER` the relay mints a fresh pepper per
process, so **every restart resets every rate-limit bucket** — the invite-redemption brute-force
limit and the prekey-drain limit included (AUDIT 5.24). A deploy is a restart, so on this box the
limits reset every time it is updated.

It is optional because it is a genuine trade-off, argued in `BACKEND.md` §5: a fixed pepper makes
the Redis bucket keys stable for as long as the value lives, so two dumps taken weeks apart can be
correlated. On a box that is deployed to deliberately and rarely, surviving restarts is worth more.

**"After the deploy" is a precondition, not a preference — and the first attempt at this proved
why.** Run on 2026-07-30 against a box still on `9a279a4`, the original procedure printed
`already set or absent` and stopped. The cause was neither: the key was **absent from `.env`
entirely**, because `.env` is gitignored and machine-local, so it was generated from the older
`.env.example` and **a deploy never regenerates it**. The original `sed` only matched an existing
empty `RELAY_RATELIMIT_PEPPER=` line, so on this box it could never have matched, at any point,
however many times it was run. It now appends when the key is missing.

Deploy first, in two stages, so that a failure tells you which change caused it:

```sh
cd ~/cipher && git pull --ff-only
cd server && docker compose up -d --build api
curl -s -o /dev/null -w '%{http_code}\n' https://relay.mgchatman.app/health   # expect 200
```

Only once that is healthy, set the pepper:

```sh
cd ~/cipher/server
# A file with no trailing newline would concatenate the append onto the previous
# variable and corrupt it silently.
[ -n "$(tail -c 1 .env)" ] && echo >> .env
if grep -q '^RELAY_RATELIMIT_PEPPER=' .env; then
  echo "already set — stopping, nothing changed"
else
  # AUDIT 1.10's spelling: `head` is the PRODUCER, so there is no SIGPIPE. Hex, not
  # base64. Never echoed: this value is a secret and belongs only in .env.
  PEPPER="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  printf 'RELAY_RATELIMIT_PEPPER=%s\n' "$PEPPER" >> .env
  unset PEPPER
  echo "appended"
fi
docker compose up -d api
```

Check the shape without printing the value — 32 bytes as hex is 64 characters:

```sh
awk -F= '/^RELAY_RATELIMIT_PEPPER=/{print "value_length=" length($2)}' .env   # expect 64
```

Then confirm the warning is **gone**, which is the only observable that says the relay actually
read it:

```sh
docker compose logs api --since 2m | grep -c RATELIMIT_PEPPER   # expect 0
```

> **The trap in that last check, and it is R2 exactly.** A build that predates the warning cannot
> emit it, so `grep -c` returns **0 on an old build too** — the same number that means success. On
> 2026-07-30 the pre-deploy count was 0 while the pepper was not merely unset but unsupported. The
> zero is only evidence if you have seen the count be **1** first: deploy, observe the warning
> appear, then set the value and observe it go away. If you never saw the 1, you have measured
> nothing.

Rotating the value later resets every bucket once — the same effect a restart used to have every
time.

### H.1 DNS

In the name.com panel: an `A` record for the API host → the VPS IPv4, and `AAAA` → the IPv6 if
you are keeping v6 reachable. Then per **P5.S04**: a `CAA` record restricting issuance to
Let's Encrypt, DNSSEC if the registrar supports it, and no records that are not needed.

```sh
dig +short A relay.mgchatman.app
dig +short AAAA relay.mgchatman.app
dig +short CAA relay.mgchatman.app
```

The name enters public Certificate Transparency logs at first issuance, permanently. That is the
point of no return `INFRASTRUCTURE.md` flags.

### H.2 Nginx, HTTP only, for the ACME challenge

```sh
sudo apt-get install -y nginx certbot
sudo mkdir -p /var/www/acme/.well-known/acme-challenge
# Deliberately minimal and temporary: the real file (H.5) names certificate paths that
# do not exist until H.3, so installing it here fails `nginx -t`.
sudo tee /etc/nginx/sites-available/cipher >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name relay.mgchatman.app;
    # Even this temporary block sets it: without it the server inherits nginx.conf's
    # combined format into /var/log/nginx, which the stock logrotate keeps for 14 days
    # (AUDIT 5.29). H.5 replaces this file, but "temporary" is how a log starts.
    access_log off;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}
EOF
sudo ln -sf /etc/nginx/sites-available/cipher /etc/nginx/sites-enabled/cipher
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Removing the default site matters: it answers on the bare IP and announces that something is
here.

### H.3 Certificate

```sh
sudo certbot certonly --webroot -w /var/www/acme \
  -d relay.mgchatman.app \
  --key-type ecdsa --reuse-key \
  --agree-tos --register-unsafely-without-email
```

**No registration email is supplied.** Let's Encrypt ended expiration-notification emails in
June 2025 and no longer stores email contacts on ACME accounts, so an address provides no renewal
safety here. `--register-unsafely-without-email` is Certbot's explicit non-interactive opt-out.
Treat the renewal dry run below and independent certificate-expiry monitoring as the alert path.

**`--reuse-key` is not optional.** Certbot generates a *new* private key on every renewal by
default. The iOS client pins the SPKI (P5.S08, `BACKEND.md` §9.1 rule 5) and fails closed, so a
rotated key at renewal is a total outage for every installed app — roughly 60 days after launch,
with no server-side fix. Confirm it stuck:

```sh
sudo grep -E 'reuse_key|key_type' /etc/letsencrypt/renewal/relay.mgchatman.app.conf
```

Generate the **backup key** now, while the tooling is here. `BACKEND.md` §9.1 rule 2 requires
shipping two pins — current, plus a key not yet in use — because one pin plus one lost key is a
permanently bricked client. P5.S06 consumes this:

```sh
sudo openssl ecparam -name prime256v1 -genkey -noout -out /etc/ssl/private/cipher-backup.key
sudo chmod 600 /etc/ssl/private/cipher-backup.key
sudo openssl ec -in /etc/ssl/private/cipher-backup.key -pubout -outform der \
  | openssl dgst -sha256 -binary | openssl base64
```

That base64 digest is a **public** value and is safe to record. The key file is not, and it must
survive any host move — see `INFRASTRUCTURE.md` § the constraint.

Renewal must reload Nginx:

```sh
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nsystemctl reload nginx\n' \
  | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx >/dev/null
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx
sudo certbot renew --dry-run
```

### H.4 The log format, and its lifetime

`§3.6` allows the client IP for triage on a short TTL. It does not allow the request path, which
identifies *who was fetched* — so the format below carries the method and status and no URI at
all. Rotation is what makes "short TTL" true rather than aspirational.

```sh
# The file lives in the repository so it is reviewable in a diff and checked by a gate
# (AUDIT 5.29). Copy it rather than retyping it; `Scripts/verify-nginx-config.py` asserts
# the properties of the committed copy, and a hand-edited box is one nothing verifies.
scp server/deploy/nginx/00-cipher-hardening.conf cipher-staging:/tmp/
ssh cipher-staging 'sudo install -m 0644 -o root -g root \
    /tmp/00-cipher-hardening.conf /etc/nginx/conf.d/00-cipher-hardening.conf && \
    rm -f /tmp/00-cipher-hardening.conf'

# The earlier name, if this box predates the rename. Leaving both installed defines
# log_format twice and nginx -t fails with "duplicate log_format".
ssh cipher-staging 'sudo rm -f /etc/nginx/conf.d/00-cipher-log-format.conf'

sudo tee /etc/logrotate.d/cipher-nginx >/dev/null <<'EOF'
# 24 hours, and 'rotate 1' so yesterday's file is the only history that exists.
# The retention policy is the strongest control this service has; a log that
# outlives it reintroduces exactly what the database deletes on delivery.
/var/log/cipher/*.log {
    daily
    rotate 1
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
EOF
sudo logrotate --debug /etc/logrotate.d/cipher-nginx
```

**This is why the logs live in `/var/log/cipher/` and not `/var/log/nginx/`.** Ubuntu's stock
`/etc/logrotate.d/nginx` globs `/var/log/nginx/*.log` at `rotate 14`, which silently claims any
file put there — logrotate reports `error: nginx:1 duplicate log entry` and which rule wins
depends on filename ordering, which is no basis for a retention guarantee. Verify there is no
collision, and note that grepping the stock file for the log's *name* will not find it because
the overlap is via a glob:

```sh
sudo mkdir -p /var/log/cipher && sudo chown root:adm /var/log/cipher && sudo chmod 750 /var/log/cipher
sudo logrotate --debug /etc/logrotate.conf 2>&1 | grep -i duplicate   # must print nothing
```

### H.5 The real server block

```sh
# Same reasoning as H.4: the committed file is the one `Scripts/verify-nginx-config.py`
# checks, so the box must run that file rather than a copy someone retyped.
scp server/deploy/nginx/cipher.conf cipher-staging:/tmp/
ssh cipher-staging 'sudo install -m 0644 -o root -g root \
    /tmp/cipher.conf /etc/nginx/sites-available/cipher && rm -f /tmp/cipher.conf'
ssh cipher-staging 'sudo ln -sf /etc/nginx/sites-available/cipher /etc/nginx/sites-enabled/cipher'
ssh cipher-staging 'sudo rm -f /etc/nginx/sites-enabled/default'
ssh cipher-staging 'sudo nginx -t && sudo systemctl reload nginx'
```

Verify from the Mac:

```sh
curl -sS https://relay.mgchatman.app/health
curl -sSI https://relay.mgchatman.app/health | grep -i strict-transport
openssl s_client -connect relay.mgchatman.app:443 -tls1_3 </dev/null 2>/dev/null | head -5
# TLS 1.2 must be refused:
openssl s_client -connect relay.mgchatman.app:443 -tls1_2 </dev/null 2>&1 | grep -i 'alert\|failure'
# Bare IP must give nothing:
curl -skI https://<IP>/health
```

### H.6 Remediating a box that predates AUDIT 5.29

A box installed before this finding logs the port-80 redirect and the catch-all default
server through nginx's inherited **combined** format into `/var/log/nginx/`, which the
stock logrotate keeps for fourteen daily generations. Applying H.4 and H.5 stops new
lines being written; it does not remove what is already there.

Run the two installs above first, then:

```sh
# 1. Confirm the box now matches the committed files, byte for byte. A drifted copy is
#    the case the gate cannot see, because the gate reads the repository.
ssh cipher-staging 'sudo cat /etc/nginx/sites-available/cipher' \
  | diff -u server/deploy/nginx/cipher.conf - && echo "site config matches"
ssh cipher-staging 'sudo cat /etc/nginx/conf.d/00-cipher-hardening.conf' \
  | diff -u server/deploy/nginx/00-cipher-hardening.conf - && echo "hardening config matches"

# 2. Every server block must now name its own access_log. Expect one line per server.
#    Anchored: a bare `grep -c access_log` returns 6, because this file explains each
#    directive in a comment directly above it (R3, the same trap as G.1's cap_drop check).
ssh cipher-staging 'sudo grep -cE "^[[:space:]]*access_log[[:space:]]" /etc/nginx/sites-available/cipher'   # 3

# 3. Prove nothing new lands in the stock log. Touch the redirect and the bare IP, then
#    check the file has not grown.
#
#    `sudo sh -c`, not `sudo wc -c < file`. The redirection is performed by the LOGIN
#    shell before sudo ever runs, so the unprivileged user opens a 0640 root:adm file
#    and the command fails with "Permission denied" every time, on a correctly
#    configured box. Written the wrong way, this step could never have passed.
ssh cipher-staging "sudo sh -c 'wc -c < /var/log/nginx/access.log'"
curl -s -o /dev/null http://relay.mgchatman.app/health
curl -sk -o /dev/null https://<IP>/health || true
ssh cipher-staging "sudo sh -c 'wc -c < /var/log/nginx/access.log'"   # unchanged

# 3b. The positive control, and step 3 proves nothing without it. A stock log that does
#     not grow is also what a box serving no traffic looks like — so confirm the request
#     arrived by watching the log it is SUPPOSED to land in. Note the path: the relay's
#     log is under /var/log/cipher/, deliberately outside the directory stock logrotate
#     globs at rotate 14.
ssh cipher-staging "sudo sh -c 'wc -c < /var/log/cipher/cipher-access.log'"
curl -s -o /dev/null https://relay.mgchatman.app/health
ssh cipher-staging "sudo sh -c 'wc -c < /var/log/cipher/cipher-access.log'"   # larger

# 3c. And the line itself carries no request path, user agent or referrer.
ssh cipher-staging "sudo sh -c 'tail -1 /var/log/cipher/cipher-access.log'"
#    Expect five fields: client IP, method, status, bytes, duration. Nothing else.

# 4. The version banner is gone from the redirect, not only from the TLS vhost.
curl -sI http://relay.mgchatman.app/ | grep -i '^server:'      # "nginx", no version
```

**Then destroy the history.** This is the part that actually discharges the finding: the
accumulated files hold client IPs, full request paths, user agents and referrers going
back two weeks, and §3.1's argument is that deletion — not encryption — is the control.

```sh
# Irreversible. Read step 1 of this section first: if the configs do not match, fix that
# before deleting, or the box starts writing new ones immediately.
ssh cipher-staging 'sudo sh -c "rm -f /var/log/nginx/access.log.* /var/log/nginx/error.log.* && \
  : > /var/log/nginx/access.log && : > /var/log/nginx/error.log"'
ssh cipher-staging 'sudo ls -l /var/log/nginx/'   # two empty files, no rotated generations
```

Truncating rather than unlinking the two live files: nginx holds them open, so deleting
them leaks the inode until a reload and the next write goes nowhere visible.

**Rollback.** Nothing here changes reachability, and the previous configuration is in
Git — `git show HEAD~1:server/deploy/nginx/cipher.conf` — so a bad edit is recovered by
reinstalling the older file and reloading. `nginx -t` runs before every reload above, so
a syntactically broken config is refused rather than served. The log deletion has no
rollback by design.

---

## Stage I — exit criterion

**P5.S05 is done when an external port scan shows only 22, 80 and 443.** Run it from the Mac, not
the box; `ufw status` is a statement of intent, a scan is evidence.

```sh
brew install nmap        # if needed
nmap -Pn -p- -T4 <IPv4>
nmap -6 -Pn -p- -T4 <IPv6>       # if an AAAA record exists
```

A full 65535-port scan against a DROP firewall is slow — every filtered port waits out its
timeout. For a quick check while it runs, name the ports that would actually matter:

```sh
nmap -Pn -T4 -p 22,80,443,5432,6379,8080,2375,2376 <IPv4>
```

Read the three states precisely, because two of them are fine and they do not mean the same thing:

- **open** — something is listening and reachable. Correct only for 22, and for 80/443 after H.
- **filtered** — UFW dropped the packet. This is what 5432, 6379, 8080 and the Docker daemon
  ports must be.
- **closed** — the firewall *allowed* it and the kernel sent a RST, i.e. nothing is listening.
  Expected on 80/443 before Nginx exists. It is not a firewall failure, but on any other port it
  would mean a rule is missing.

Anything **open** beyond 22/80/443 — particularly 5432 or 6379 — means Stage C's Docker warning
applies and the compose file has been changed. Stop and fix before continuing.

Final checklist, each backed by a command above:

| | Check | Evidence |
|---|---|---|
| B | Password auth refused | `sshd -T`, plus the negative test |
| B | Root login refused | negative test 3 |
| C | Only 22/80/443, v4 **and** v6 | `nmap -p-` from the Mac |
| D | Unattended upgrades resolve | `unattended-upgrade --dry-run` |
| E | `sshd` jail actually running | `fail2ban-client status sshd` |
| F | Container logs bounded | `/etc/docker/daemon.json` |
| G | Postgres/Redis unpublished | `ss -tlnp`, `nc` from the Mac |
| H | Trusted proxy is the bridge subnet, not loopback | `docker inspect … \| grep RELAY_TRUSTED_PROXY` |
| H | Access log carries no request URI | `head /var/log/nginx/cipher-access.log` |
| H | TLS 1.3 only, 1.2 refused | `openssl s_client` |
| H | Renewal reuses the key | `grep reuse_key …renewal/*.conf` |

---

## Our own backup, and the restore drill (P9.S05)

Separate from the provider snapshot below, and for the opposite reason: that one keeps too much and
cannot be declined, this one keeps deliberately little and is the only copy we control.

**What is in it:** `accounts` and `session_tokens`. Nothing else — see `BACKEND.md` §4 for why each
other table is excluded, and `AUDIT.md` **4.16** for the cost of including the second one.
`server/deploy/backup.sh` is an allow-list and refuses to write an unencrypted archive.

**Key custody, and the one rule that matters.** The archive is encrypted with `openssl cms` to a
**recipient certificate**, so the box holds only a public key and *cannot decrypt its own backups*.
The private half must live off the host — an operator machine or offline media. Putting it on the
box would place the key beside the ciphertext, which is the state `THREAT_MODEL.md` §1.1 already
assumes the adversary reaches.

Create the recipient pair **on the operator machine, not here**:

```sh
openssl req -x509 -newkey rsa:3072 -keyout cipher-backup.key -out cipher-backup-cert.pem \
  -days 3650 -nodes -subj "/CN=cipher-backup"
```

Copy only `cipher-backup-cert.pem` to the box. Guard `cipher-backup.key` like the TLS key: losing it
makes every archive unreadable, and leaking it makes every archive readable.

**Take a backup:**

```sh
~/cipher/server/deploy/backup.sh --recipient ~/cipher-backup-cert.pem --out /var/backups/cipher
```

**Restore.** Never restore over the live database as a first move. Restore into a scratch database,
verify it, and only then decide — a restore that turns out to be wrong is otherwise unrecoverable:

1. `openssl cms -decrypt -inform DER -in <archive> -out plain.sql -inkey cipher-backup.key`
   (on the operator machine, where the key is).
2. Create a scratch database and apply `server/internal/store/migrations/*.sql` in order — **the
   migrations are the schema of record, not the archive.** The archive carries rows only.
3. Load `plain.sql` into the scratch database and check the counts below.
4. Only then promote it, and immediately **revoke all sessions** — this is what closes AUDIT 4.16's
   window, in which a sign-out performed after the backup is undone by the restore.
5. `shred -u plain.sql`.

**Rollback:** the scratch database is the rollback. Drop it (`DROP DATABASE cipher_drill;`) and
nothing has changed. Up to step 4 the live database has not been written to at all.

**Drill executed 2026-08-11**, on this box, into a scratch database, live database read-only
throughout. OBSERVED: the archive was `data` to `file(1)` with **0** readable `COPY` strings;
decryption returned a dump naming exactly `accounts` and `session_tokens`; restore into the scratch
database returned **5 accounts and 3 session tokens, matching live exactly**, with identity-key
lengths all in range and every token row still joining its account; and `messages`, `attachments`,
`invites`, `one_time_prekeys` and `push_tokens` all came back **0** — the retention policy holding
through a real restore. Teardown dropped the scratch database and the live database was unchanged
(`accounts=5 messages=1`). The drill used a throwaway keypair generated for it and destroyed after;
the real procedure never puts the private half on the host.

**Cadence and objectives:** see `INFRASTRUCTURE.md` § Backup objectives for RPO/RTO and what each
data class costs on loss.

---

## The OVH daily backup

`INFRASTRUCTURE.md` closes on an open decision, and the control panel is open at Stage A, so
decide it here. OVH's included daily snapshot images the whole disk, Postgres volume included, so
a message deleted on delivery at 14:00 survives in a 03:00 snapshot for up to 24 hours after the
relay has forgotten it. Message and attachment content remains ciphertext, and private E2E keys
remain on-device, but the image also contains public identity/prekey material, account and routing
metadata, server configuration/secrets, and TLS private keys.

Preference is to **disable it** in the panel: delete-on-delivery is the strongest server-side
control there is, and a 24-hour hole in it should be a decision rather than a default. If it
cannot be disabled, record it as a stated residual in `AUDIT.md` and `BACKEND.md` §4 — the one
outcome that is not acceptable is leaving it undecided.

---

## Deliberately not done

- **SSH on a non-standard port.** The exit criterion names 22. Moving it stops log noise, not
  attackers, and costs a documented invariant.
- **Rootless Docker.** Real improvement, real complexity around the blob volume and healthchecks.
  Revisit at P9.S01 with a production host to compare against.
- **HSTS preload / `includeSubDomains`.** Staging. See H.4.
- **Nginx rate limiting.** The relay's limits are tested and Redis-backed; a second, untested
  limiter in front of them would obscure which one refused a request.
- **Host-level intrusion detection (auditd, AIDE).** Nothing consumes the output. An alert nobody
  reads is not a control.
