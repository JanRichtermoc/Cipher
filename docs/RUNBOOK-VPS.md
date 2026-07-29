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
| G | done | `main` @ `9a279a4`. All three containers healthy, 8080 on loopback only. Secrets generated on the box. |
| H.0 | done | `RELAY_TRUSTED_PROXY=172.18.0.1/32` — the bridge **gateway**, not the subnet. Verified live both ways: rotating `X-Real-IP` through the host's published port gets fresh buckets, the same rotation from inside the `postgres` container still hits `429`. |
| H.1–H.5 | done | `relay.mgchatman.app`, Let's Encrypt ECDSA leaf expiring 2026-10-27, `reuse_key = True` confirmed in the renewal config. TLS **1.3 only** — and see AUDIT 5.16, because it was 1.2-accepting at first while the config read as 1.3-only, and the first probe reported a false pass. Verified end to end from the internet: forging `X-Real-IP` per request does **not** escape the rate limit (8 requests, one bucket, throttled at the 6th). Access log carries no request URI. |
| I | done | Post-H full scan: **22, 80, 443 open; everything else filtered**, both families. Pre-H the same scan showed 65532 filtered / 2 closed / 1 open, confirming 80 and 443 only became reachable when Nginx was deployed. |

---

## 0. Before the first command

**Ownership.** Stages A–G need shell access and are the operator's to run, or Claude's once the
`cipher-staging` alias resolves. Stage H additionally needs a DNS record and an ACME email, which
only the operator can supply. §H.0 is the one part of H that needs neither — do it first.

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
sudo tee /etc/nginx/sites-available/cipher >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name relay.mgchatman.app;
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
  --agree-tos -m jandajhdbahc@seznam.cz --no-eff-email
```

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
sudo tee /etc/nginx/conf.d/00-cipher-log-format.conf >/dev/null <<'EOF'
# THREAT_MODEL.md §3.6. Deliberately absent: $request / $request_uri (a populated
# path such as /v1/keys/3f2b… is a metadata record hiding in a log line, which is
# why httpx.pattern() strips it from application logs), $http_user_agent and
# $http_referer (fingerprinting surface, no triage value for a native-app API).
log_format minimal '$remote_addr $request_method $status $body_bytes_sent $request_time';
EOF

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
sudo tee /etc/nginx/sites-available/cipher >/dev/null <<'EOF'
# Unmatched Host (scanners hitting the bare IP) gets nothing at all.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    # ssl_protocols MUST be here, not only in the relay block below. nginx
    # negotiates the TLS version from the DEFAULT server's context for the
    # listening socket, BEFORE SNI selects a virtual server — so a per-server
    # ssl_protocols is applied too late to refuse anything. Omit this and
    # Ubuntu's nginx.conf line 33 ("TLSv1 TLSv1.1 TLSv1.2 TLSv1.3") governs the
    # socket: the config reads as 1.3-only and the server accepts 1.2.
    # `nginx -t` passes either way. AUDIT 5.16.
    ssl_protocols TLSv1.3;
    ssl_reject_handshake on;
    return 444;
}

server {
    listen 80;
    listen [::]:80;
    server_name relay.mgchatman.app;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}

server {
    # The `http2` parameter of `listen`, not the `http2 on;` directive: that
    # directive arrived in nginx 1.25.1 and 24.04 ships 1.24.0, where it is an
    # "unknown directive" and nginx -t fails. This form works on both.
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name relay.mgchatman.app;

    ssl_certificate     /etc/letsencrypt/live/relay.mgchatman.app/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.mgchatman.app/privkey.pem;

    # 1.3 only. The sole client is a pinned iOS app; there is no legacy peer to
    # accommodate, and every downgrade-negotiation problem disappears with 1.2.
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    # Tickets are a forward-secrecy hazard: one stolen ticket key retrospectively
    # opens every session that used it.
    ssl_session_tickets off;
    # No ssl_stapling: Let's Encrypt retired OCSP in favour of CRLs.

    # Staging: short, no includeSubDomains, no preload. A long max-age on a name
    # that may be repurposed is a commitment browsers will not let you withdraw.
    add_header Strict-Transport-Security "max-age=300" always;
    server_tokens off;

    # THREAT_MODEL.md §3.6 permits IP retention on "a short operational TTL",
    # and httpx.Log deliberately keeps the client IP out of application logs so
    # that triage data lives here instead, with its own lifetime. So: log, but
    # on the 'minimal' format defined in nginx.conf below, and rotate at 24h.
    #
    # The default 'combined' format is NOT usable: it logs $request, which means
    # /v1/keys/3f2b… — the populated-path leak that httpx.pattern() exists to
    # prevent in application logs. Recording it in the proxy instead would defeat
    # the control rather than relocate it. The minimal format has no URI.
    # NOT under /var/log/nginx: the stock logrotate globs that directory at
    # rotate 14 and would silently claim these files, making the 24h retention
    # claim false. logrotate calls the collision a "duplicate log entry" and the
    # winner depends on filename ordering. See H.4.
    access_log /var/log/cipher/cipher-access.log minimal;
    error_log  /var/log/cipher/cipher-error.log warn;

    # Blobs are capped at 100 MiB by the relay. 101m lets the RELAY produce its
    # own tested 413 instead of Nginx short-circuiting with an untested one.
    client_max_body_size 101m;
    client_body_timeout  120s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto https;
        # SET, not add: both of these OVERWRITE whatever the client sent, which
        # is the entire reason the relay may trust them. X-Forwarded-For is
        # deliberately collapsed to the single real peer rather than appended to
        # — a forwarded chain is a list of values an attacker chose. See H.0.
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_request_buffering off;
        proxy_read_timeout 120s;
    }
}
EOF
sudo nginx -t && sudo systemctl reload nginx
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

## The OVH daily backup

`INFRASTRUCTURE.md` closes on an open decision, and the control panel is open at Stage A, so
decide it here. OVH's included daily snapshot images the whole disk, Postgres volume included, so
a message deleted on delivery at 14:00 survives in a 03:00 snapshot for up to 24 hours after the
relay has forgotten it. Ciphertext only — keys never touch the server — so what it extends is
*metadata*: who had mail waiting.

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
