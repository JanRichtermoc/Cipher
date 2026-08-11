# Infrastructure — hosting, registrar, and access

Where the relay runs, why there, and how a session reaches it. Written during P5 because the
choice was made across a conversation and a decision that lives only in a chat is a decision
nobody can review.

Read with [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7 (jurisdiction) and [`BACKEND.md`](BACKEND.md)
§9 (deployment shape).

---

## Status

| | |
|---|---|
| **Staging VPS** | OVH VPS-1 — **purchased 2026-07-29** |
| **Domain** | name.com, via the GitHub Student Developer Pack |
| **Production VPS** | Does not exist. Separate purchase at **P9.S01**, same hardening bar. Do not reuse staging. |

---

## Provider: OVHcloud

**VPS-1** — 2 vCores, 4 GB RAM, 40 GB NVMe, unlimited traffic, public IPv4 included.
Roughly €5–6/month including Czech VAT. Monthly commitment, deliberately not annual.

Datacentre must be **Gravelines or Roubaix (FR)** or **Frankfurt (DE)**. Not Beauharnois,
not the US, not Singapore — that is the whole §3.7 point.

`THREAT_MODEL.md` §3.7 already named OVH alongside Hetzner, so this choice needed no amendment
to the threat model. That is the reason it was preferred over otherwise-equivalent options: a
provider the threat model has already reasoned about costs nothing to adopt.

**Monthly, not annual.** OVH discounts 12- and 24-month commitments. The discount is worth
roughly €10 and it removes the ability to move hosts, which the pin constraint below makes a
live consideration. Ten euros is not worth losing that.

### Providers considered and rejected

| Provider | Why not |
|---|---|
| **Hetzner** (🇩🇪) | The best technical and jurisdictional fit, and still the first choice if OVH ever disappoints. Rejected only because new accounts require a **€25 advance payment** to verify. That is *not* a fee — it is account credit that pays your invoices, about four months of hosting — but it is unrecoverable until the account is fully closed, and the upfront amount was the blocker. |
| **Oracle Cloud** (🇺🇸) | Always Free ARM would have cost **€0**, and an account was created. Abandoned on two counts: the A1.Flex shape returned **"Out of capacity"** in the chosen home region, which is chronic rather than transient; and Oracle is a US company, so an EU region gives data residency but not distance from US legal process. The free tier was also **halved without announcement** on 2026-06-15 (4 OCPU/24 GB → 2 OCPU/12 GB), which is the deeper objection — a tier whose terms move silently is a poor foundation. |
| **DigitalOcean** (🇺🇸) | $200 of GitHub Student credit was available and **expired 2026-07-31**, with DigitalOcean ending the student programme entirely. Unused credit is forfeited: at ~€6/month the two remaining days would have consumed **under one dollar** of it. Taking DigitalOcean *because of* the credit would have meant choosing a US provider against §3.7 and paying full price from day three. |
| **Netcup** (🇩🇪) | Genuinely competitive, but not named in `THREAT_MODEL.md` §3.7. Choosing it would have required amending the threat model first, for no advantage over OVH. |

The general lesson, recorded because it nearly cost real money: **an expiring credit is not a
reason to choose a provider.** Work out what it can actually buy before it lapses.

---

## Registrar and domain

**name.com**, through the GitHub Student Developer Pack — one domain free for the first year.

- `.com` is **not** eligible. `.app` and `.dev` are, and both are on the HSTS preload list, so
  browsers force HTTPS for the whole TLD. That benefit is **marginal here**: Cipher is a native
  app with ATS and certificate pinning, so preload only helps someone typing the domain into
  Safari. It is a tiebreaker, not a reason.
- Premium domains are not covered by the offer. The checkout total must read `$0.00`.
- **WHOIS privacy, registrar lock and auto-renew must all be on.**
- Year two is charged at the standard rate. Note it: this domain gets pinned into the shipped
  app, so letting it lapse would leave the app pointing at whoever registers it next.

**Whatever name is chosen appears in public Certificate Transparency logs, permanently and
searchably.** Pick something that does not identify the operator or advertise what the service
is. This is not a secret you can retract later.

---

## Access

The relay is reached from the developer's own machine. There is no shared credential and
nothing needs to be transmitted.

```
Host cipher-staging
    HostName <server IP>
    User ubuntu
    IdentityFile ~/.ssh/cipher_staging
    IdentitiesOnly yes
```

- The private key `~/.ssh/cipher_staging` never leaves the Mac.
- DNS records are created by hand in the name.com panel, so **no registrar API token needs to
  exist**. P5.S03 anticipated handing one over; it turned out to be unnecessary, and a token
  that does not exist cannot leak.
- Relay secrets (`server/.env`) are generated **on the server** and are in neither the
  repository nor any conversation.

**Nothing secret goes into a chat transcript.** Not the OVH password, not a private key, not a
database password. The hostname and IP are public the moment DNS resolves and are fine to
discuss.

### The emailed password

OVH emails the initial `ubuntu` credentials in plaintext. That password is live on a
publicly-reachable host from the moment the VPS is provisioned, and OVH — unlike Oracle — applies
no default-deny firewall at either the network or the image level. **Disabling password
authentication is therefore the first hardening action, not a later one.**

---

## The constraint that decides when hosts can still change

**P5.S06 extracts the TLS SPKI pins. P5.S08 ships them inside the iOS app.**

Before P5.S08, hosts are disposable: DNS is one record, ACME re-issues certificates, and the
database holds almost nothing because delivered messages are deleted and redeemed invites are
gone. A migration is a `pg_dump` measured in kilobytes.

After P5.S08, moving hosts means **either carrying the TLS private key across, or shipping an
app update**. `BACKEND.md` §9.1 rule 5 already requires pinning the SPKI rather than the
certificate, which is exactly what makes carrying the key sufficient.

Flag this before running P5.S06.

---

## Backup objectives (P9.S05)

Our own backup, distinct from the provider snapshot below. Procedure and the executed drill are in
[`RUNBOOK-VPS.md`](RUNBOOK-VPS.md) § Our own backup; scope and its reasoning in
[`BACKEND.md`](BACKEND.md) §4.

| Objective | Value | Why this and not tighter |
|---|---|---|
| **RPO** | 24 hours | The only data with a real recovery point is `accounts` and `session_tokens`, both of which change rarely in a five-person circle: an account is created once, a token rotates every few weeks. A tighter RPO would copy the same rows more often and buy nothing, while lengthening AUDIT 4.16's revocation-resurrection window is the one thing frequency *does* affect — so 24h is also the bound on that window. |
| **RTO** | ~1 hour to a serving relay | Restore is: redeploy from git (the schema is the migrations, in git), load two tables, revoke all sessions. Nothing waits on a large transfer — the archive is kilobytes, because it deliberately holds almost nothing. |
| **RTO, full session capability** | up to 48 hours | Prekeys are deliberately not backed up. Peers cannot start a **new** session with a restored account until its owner's next rotation, which is bounded by `MessageRepository.preKeyRotationInterval` (48h) regardless of any count. **Established sessions are unaffected** — the ratchet lives on the device, so existing conversations keep working through a restore. |

What each data class costs on loss, since "back up the database" would answer all of these the same
way and three of the answers are that losing it is correct:

| Data class | In the backup? | Cost of losing it |
|---|---|---|
| Account identity (`accounts`) | **Yes** | Unrecoverable. The `aci` is the address peers hold and the identity key is what their safety numbers are of; a new invite mints a *different* account. |
| Session credential (`session_tokens`) | **Yes** | Unrecoverable by the client: rotation needs the old token and redemption creates a new account. This is why it is included, and the inclusion is AUDIT **4.16**. |
| Message ciphertext | No | Correct outcome, not a gap (`BACKEND.md` §4). Undelivered messages are lost; delivered ones were already deleted. |
| Attachment blobs | No | As above, and they live outside Postgres. |
| Public prekey material | No | Self-healing within one 48h rotation; see the RTO row above. |
| Invites | No | Deliberate. Restoring one resurrects a live account-creation credential. |
| Push tokens | No | Deliberate. Metadata that outlives the message (P7.S03); the device re-registers. |
| Operational server secrets (`server/.env`, TLS private keys, the pin backup key) | **No — separate custody** | A different domain entirely, and not something a database backup should ever carry. They are the operator's to hold offline. Losing the rate-limit pepper resets buckets (harmless); losing `RELAY_PUSH_TOKEN_KEY` makes stored push tokens undecryptable, which fails closed and resolves on re-registration; losing the TLS key is the pinning emergency `BACKEND.md` §9.1 rule 2 keeps a second pin for. |

The archive is encrypted to a recipient certificate, so **the host cannot decrypt its own backups**
and a seizure of the box yields the archive without a way into it. The private half never goes on
the host.

---

## Decided — the backup cannot be disabled, and is carried as a residual

**2026-07-29.** The preference was to disable it. **OVH provides no way to.** The operator checked
the control panel; the included daily backup is not optional on this product.

So it is recorded rather than written around: **`AUDIT.md` 4.8**, status ACCEPTED, and
`BACKEND.md` §4 now carries the exception directly under the rule it contradicts. The honest
statement is that "acknowledged means gone" is true of the database and not of the host, for up
to 24 hours.

**Why this is tolerable at staging and must be re-argued for production.** The snapshot holds
message and attachment ciphertext, public identity/prekey material, account and routing metadata,
server configuration/secrets, and TLS private keys. It does not hold plaintext message content or
private E2E keys. This does not widen the adversary set, because OVH already holds the live disk and
the same legal process reaches both; it widens the retention window. Encrypting the volume would not
help, since a hypervisor snapshot of a running system captures a filesystem whose key is already in
memory.

**This becomes a selection criterion at P9.S01.** Jurisdiction was the criterion that chose OVH
(§3.7). "Can provider snapshots be declined?" is now a second one, and it is worth asking *before*
buying rather than discovering afterwards — Hetzner, already the technical first choice and
rejected only over a €25 advance payment, bills backups as an opt-in extra.

### The original question, for the record

OVH includes a *"daily backup of the previous 24 hours"* on VPS. It conflicts, mildly, with
`BACKEND.md` §4:

> Backups cover schema and account rows only — losing undelivered messages in a restore is the
> correct outcome, not a gap to fix.

A provider snapshot images the whole disk, including the Postgres volume. A message deleted on
delivery at 14:00 can therefore still exist in a snapshot taken at 03:00, for up to 24 hours
after the relay has forgotten it.

**How much this matters:** message bodies and attachments remain encrypted, and private E2E keys
remain on-device. The image is still not “ciphertext only”: it also contains public key material,
metadata, TLS private keys, and service configuration/secrets. OVH already has those on the live
host; the snapshot extends their retention by up to 24 hours.

Two options were on the table:

1. Disable the included backup in the OVH control panel, if it can be disabled.
2. Accept it and record it as a stated residual in `AUDIT.md` and `BACKEND.md` §4.

**(1) turned out not to exist on this product, so (2) it is.** See the top of this section.
