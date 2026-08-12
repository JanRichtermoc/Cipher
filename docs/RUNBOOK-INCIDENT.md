# Cipher — incident response runbook

Written to be **walked at 3am by one person under pressure**, which is the only condition it will
ever be used in. Every step is a command or a decision, in order, with the expected result beside it.

**This document owns no facts.** Pin values and the certificate rotation procedure belong to
[`BACKEND.md`](BACKEND.md) §9.1; host procedures to [`RUNBOOK-VPS.md`](RUNBOOK-VPS.md); backup and
restore to that runbook's § Our own backup; finding status to [`AUDIT.md`](AUDIT.md). Where a
procedure already exists this file routes to it rather than restating it, because a second copy of a
rotation procedure is a copy that will be a version behind when it matters.

**Scope: staging.** There is no production host yet (P9.S01). Everything here is written to survive
the cutover, but the contact points and the blast radius change when real users are on a production
relay, and this file is re-read at P9.S02.

---

## 0. The first five minutes

In order. Do not skip to the interesting part.

1. **Write down the time (UTC) and what you observed.** Not what you concluded. The log is 24-hour
   (`BACKEND.md` §7), so evidence expires while you are thinking.
2. **Do not restart or redeploy anything yet.** A restart destroys the process state that says what
   happened, and `docker compose up -d --build` replaces the binary you would want to compare.
3. **Classify** with the table in §1. If two classes fit, take the more severe.
4. **Decide the one question that orders everything else:** *is the private key material still
   trustworthy?* If a TLS private key or a relay service secret may have left the host, you are in
   §3 or §4 and availability is now the cheaper thing to spend.
5. **Only then** act.

**What is never an incident response:** deleting logs, rotating a credential before you have
recorded which one was exposed, or "just re-deploying to be safe". Each destroys the evidence that
tells you whether you are done.

---

## 1. Classification

| Class | Looks like | Go to |
|---|---|---|
| **A — Relay host compromise** | Unexplained process, unexpected outbound connection, SSH access you cannot account for, package or binary you did not deploy | §2 |
| **B — TLS leaf key compromise** | Key material exposed, host compromise (A implies B), backup of the key mishandled | §3 |
| **C — Relay service secret exposure** | `server/.env` read, pasted, committed, or present in a shared log | §4 |
| **D — Client device lost or stolen** | A circle member's iPhone is gone | §5 |
| **E — Suspected impersonation** | A safety number changed without the peer rotating, or an unexpected identity-change banner | §6 |
| **F — Availability only** | Relay down, certificate expired, disk full — **no** evidence of compromise | §7 |

Class F is not an incident in this file's sense. It is `RUNBOOK-VPS.md`.

---

## 2. Class A — relay host compromise

**What is and is not at risk, before you decide anything.** The relay holds ciphertext, public
identity and prekey material, routing metadata, and its own service secrets and TLS private key. It
does **not** hold message plaintext or any private E2E key — those never leave the device
(`THREAT_MODEL.md`, plan §0.6). So a host compromise is a **metadata and availability** event and a
**key-custody** event; it is not a message-content event. Say this plainly to the circle: overstating
it destroys trust as effectively as understating it.

### 2.1 Contain

1. **Snapshot before you touch it**, if the provider panel allows one — evidence first.
2. **Cut public reachability** rather than killing the relay, so the process survives for inspection:
   ```sh
   sudo ufw deny 443/tcp && sudo ufw deny 80/tcp && sudo ufw status
   ```
3. **Do not** `docker compose down`. Containers hold the state you are about to read.

### 2.2 Preserve

```sh
docker compose ps --format '{{.Service}} {{.Status}} {{.Image}}'
docker compose logs --no-color --since 24h > ~/incident-logs.txt
ss -tulpn
sudo last -F | head -40
sudo journalctl -u ssh --since -7d --no-pager > ~/incident-ssh.txt
```
Copy those files **off the host** before eradication. Note the running image's build time — a
container reporting healthy proves only that something is serving (the trap the 2026-08-11 deploy
recorded in `RUNBOOK-VPS.md`).

### 2.3 Eradicate

A compromised host is rebuilt, not cleaned. Walk `RUNBOOK-VPS.md` from Stage A on a **new** host.
There is no step here that inspects a rootkit; if you are asking whether the box is clean, it is not.

### 2.4 Recover

1. Restore `accounts` and `session_tokens` from the encrypted backup — `RUNBOOK-VPS.md` § Our own
   backup, restore path. **Restore into a scratch database first**, always.
2. Rotate the TLS key: **§3**, and note that a host compromise means the leaf key is compromised.
3. Rotate every service secret: **§4**.
4. **Do not mass-revoke sessions.** Read §8 before you consider it — it is not the control it sounds
   like, and after a restore it is usually the wrong answer.

### 2.5 Tell the circle

Cipher has five people and no push channel, so notification is out of band and by hand. Say: what was
reached, what was **not** (message plaintext, private keys), what they must do (compare safety
numbers on next contact — §6), and what they will see (a possible identity-change banner if anyone
re-registers). Do not promise an investigation you will not run.

---

## 3. Class B — TLS leaf key compromise

**Do not improvise this.** The client pins the SPKI and **fails closed**: getting it wrong is not a
weakened control, it is every installed app permanently unable to connect, with no server-side fix.

The procedure is [`BACKEND.md`](BACKEND.md) §9.1 → *"Emergency: the leaf key is compromised"*. In
summary, and only as an index into it: reissue against the **backup key B** (every shipped client
already pins it, so no client release is needed — that is what B is for), revoke the old certificate
with `--reason keyCompromise`, then generate a new backup key and ship it as a pin in the next
release.

**The step people forget is the last one.** Until that release adopts, the service is one lost key
away from a total outage. Treat it as urgent, not as done.

Afterwards, confirm rather than assume:
```sh
Scripts/verify-pins.sh relay.mgchatman.app
```

---

## 4. Class C — relay service secret exposure

`server/.env` holds the Postgres and Redis passwords, the rate-limit pepper, and (from P8) the push
token key. **Never read the values to decide this** — that a file was exposed is enough.

| Secret | Rotate by | Cost of rotation |
|---|---|---|
| `POSTGRES_PASSWORD` | `ALTER ROLE … PASSWORD`, update `.env`, recreate `api` | Brief outage on recreate |
| `REDIS_PASSWORD` | Update `.env`, recreate `redis` and `api` | Rate-limit buckets reset — harmless |
| `RELAY_RATELIMIT_PEPPER` | Update `.env`, recreate `api` | Every bucket subject changes; limits restart from empty. Accept it |
| `RELAY_PUSH_TOKEN_KEY` | Update `.env`, recreate `api` | Stored push tokens become undecryptable. This **fails closed** (P7.S03) and resolves as devices re-register |

Rotate **all** of them if the file was exposed as a file: rotating one at a time treats the exposure
as if it were selective, and it was not.

---

## 5. Class D — a device is lost or stolen

**What the finder can reach.** Crypto records are `AfterFirstUnlockThisDeviceOnly`, so a device
seized *after* its first unlock is extractable by an attacker with that capability — the accepted
residual **AUDIT 2.1**, re-confirmed by P9.S07 item 8. The app lock is a local control and not a
defence against forensic extraction. There is **no remote wipe** and Cipher will not claim one.

1. **The device's owner** revokes their own sessions from another installation if they have one:
   `DELETE /v1/auth/all` (this is the per-account panic button and works exactly as advertised).
   If they do not have one, the operator deletes that account's rows — see §8, per-account path,
   which is safe and targeted; it is only the *mass* form that is destructive.
2. **The circle re-verifies safety numbers** with that member once they are back on a new device.
   They will appear as an identity change, because they are one.
3. Record it. A lost device is the event most likely to be the explanation for §6 later.

---

## 6. Class E — suspected impersonation

An identity-change banner means the peer's identity key is not the one you verified. Usually that is
a reinstall. The residuals that make it worth taking seriously are **AUDIT 3.8** (a circle member can
mint a sealed certificate naming another account) and **3.9**.

1. **Do not accept the new key** to make the warning go away. Sending stays blocked until
   `acceptIdentity` names the exact key shown — locked decision §0.2.1, and that block is the
   protection.
2. **Compare safety numbers out of band** — in person or over a channel the relay does not carry.
3. If they do not match, stop messaging that contact and treat it as Class A until explained.
4. If they do match, accept the key. Record what happened; a second unexplained change for the same
   peer is a different conversation.

---

## 7. Class F — availability

`RUNBOOK-VPS.md` owns this. The only thing worth repeating here: **health says only that something is
serving.** A container reporting `Up (healthy)` after a failed build is the *old* binary answering.
Check the image build time and the uptime, not the health endpoint.

---

## 8. Mass revoke — read this before using it

The roadmap lists "mass revoke" as an incident-response action. **It does not exist in a usable
form**, and that is recorded as **AUDIT 5.41**.

- `DELETE /v1/auth/all` is **per-account and self-service.** It authenticates *as* the account and
  destroys only that caller's sessions. There is no operator endpoint.
- The only operator-side action is `DELETE FROM session_tokens` in psql.

**What that actually does**, which is not "everyone signs in again":

1. The session token is the **only** credential path. Rotation needs the old token, and redeeming an
   invite creates a **new** account. So every account whose row is deleted is unrecoverable: its
   owner must redeem a fresh invite, receive a different `aci`, and re-verify safety numbers with
   every peer.
2. It is **destructive on the device, on a delay.** An ordinary 401 is non-destructive, but a
   *rotation* rejection is handled as `signOut()`, which erases local protocol state, history and
   profile. Rotation begins 7 days before a 30-day expiry, so each device erases its own history
   whenever it next enters that window — up to **23 days** later, with nothing on screen linking it
   to your action.

So a mass revoke is indistinguishable from disbanding the circle and rebuilding it, with silent
history loss along the way.

**Use these instead, in this order:**

1. **Cut reachability** (§2.1). Stops every session immediately, reverses in one command, destroys
   nothing.
2. **Rotate service secrets** (§4). Invalidates the relay's trust in its own infrastructure without
   touching account rows.
3. **Per-account deletion**, for the one account actually implicated. Targeted and already tested by
   the account-deletion cascade.
4. **Mass revoke — last resort only**, when you believe every session token has been exfiltrated
   *and* you accept rebuilding the circle. Tell everyone **first**, out of band, that their history
   will be erased and they will need a new invite. Do not do it quietly.

---

## 9. After any incident

1. Write what happened, when, what was reached, and what was ruled out — while it is fresh.
2. Open an `AUDIT.md` row for anything the incident revealed. An incident that closes with no ledger
   change either revealed nothing or was not examined.
3. Re-run the gates: `./Scripts/verify-all.sh`, and `./Scripts/verify-pins.sh <host>` if anything
   touched TLS.
4. If the response needed a step this file does not have, add it here in the same session. A runbook
   is only walkable if the last person to walk it fixed what they tripped on.
