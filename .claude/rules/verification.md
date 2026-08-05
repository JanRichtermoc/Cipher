---
paths:
  - "Scripts/**/*"
  - ".github/workflows/**/*"
  - ".github/dependabot.yml"
---

# Verification, tests, and CI

- Read `docs/AUDIT.md` §0 and §6 plus every affected script/workflow before editing a control.
- Never weaken, skip, reorder for convenience, or turn a required failure into warning output.
- A new or changed gate needs a positive control and a negative test against the exact defect. Record
  the failure reason, restore the correct source, prove success, and confirm the gate appears in the
  full verification output.
- Avoid long or infinite producers upstream of early-exiting consumers under `pipefail`. Strip prose
  and comments before scanning the control they describe. A “found nothing” check needs evidence that
  it actually scanned something.
- Derive versions, gate counts, target membership, and required tests from executable sources. Do not
  encode copied totals in documentation or workflow comments.
- Do not install dependencies, rewrite manifests, update pins, or alter CI permissions outside the
  approved scope.
- Finish with `./Scripts/verify-all.sh`; if server behavior is involved, also run the relay integration
  suite. Prove named tests and gates actually ran.
