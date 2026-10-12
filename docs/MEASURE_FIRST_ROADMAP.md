# Measure-first, not policy-first (operator direction, 2026-10-12)

**Origin**: operator review of the live posture (policy_mode=report_only + never_intercept 99 hosts +
auto-pin). His framing, recorded verbatim in spirit: *"the system should measure anyway and verify,
not create these policies — it should naturally learn to do this. We operate better in this manner
than enforce."*

## The two dials (for the record)

1. **`policy_mode`** — what the engine DOES with traffic it intercepts:
   `enforce` (act: block/rewrite/consent) · `report_only` (observe + receipt what *would* have
   happened) · `disabled`. One GLOBAL knob today.
2. **`never_intercept_hosts` (+ `auto_pin_*`)** — which traffic it touches AT ALL. Cert pinning is
   app-side behavior; MITM breaks pinned apps, so the list is a compatibility surface grown from
   evidence, and `auto_pin` (reject_threshold=2 / window=300s) is the engine already LEARNING a
   host class from observed failures. Every host on the list is an app un-broken — a freedom list,
   not a restriction list.

Scope note: the engine governs **Windows-side app traffic** (WinINET). The ecology's own internal
traffic (agents, mesh, local services) does not route through it, so neither dial gates internal
evolution.

## The direction: graduated enforcement (evidence-earned teeth)

Replace the global enforce/report_only dichotomy with **per-rule graduation**:

- Every rule starts in `report_only`: its receipts accumulate would-be-blocks and, crucially,
  **outcome signals** (did anything break in the window after a would-be block? did a pinned-host
  violation follow? did a user/app contact us?).
- A rule GRADUATES to `enforce` only when its own evidence shows the block is safe: N would-be
  blocks over T days with zero correlated breakage, zero pinning violations, zero consent regressions.
- Graduation is per-rule, automatic, and **reversible**: an enforced rule whose receipts show a
  regression de-graduates back to report_only and files a receipt. The system learns what to block
  by watching what breaks when it would have blocked — not by a static regime flip.
- The dashboard shows the graduation ladder per rule (reporting → observing → graduated) — the mode
  badge generalizes to a per-rule evidence view.

## Why this is the right shape

- Matches the operator's operating philosophy: measure, verify, let enforcement BE the learned
  outcome; no big-bang "enforce mode" that can be gotten "stuck on" or lose sight of its reasons.
- The precedent already exists in miniature: `auto_pin` learns host classes from repeated failures.
  Graduated enforcement is auto-pin's logic applied to rules instead of hosts.
- It upgrades the product story too: "enforcement earned from your own traffic's evidence" is a
  materially different claim from "we shipped a blocklist."

## Refinement (same day): rectify-first — blocking is the fallback, not the primitive

Operator, sharpening the direction: *"blocking doesn't seem right either — we should be rectifying
and researching and testing and experimenting and improving things; if something isn't working it
needs to be improved and upgraded."*

The response ladder becomes:

1. **Observe** — receipts (the substrate; already live).
2. **Rectify** — repair the traffic instead of denying it:
   - *sanitize* (strip tracking parameters, forward the useful request — it succeeds, minus the payload),
   - *neutralize* (serve a benign no-op in place of a tracker script — the page works, the tracker gets nothing),
   - *uncloak* (CNAME-uncloak first-party trackers and surface them — the engine already counts
     `dns_cname_uncloaked_total`),
   - *negotiate* (consent flows answered/streamlined rather than the request blocked).
   The engine already carries the machinery's seeds: `body_rewrite_*` counters and the rewrite path.
3. **Research + experiment** — when rectification fails, investigate why (the ecology's own method:
   read the upstream, build the repro, run the experiment, ship the fix forward).
4. **Upgrade** — every incident ends in a capability improvement, not a new deny entry.
5. **Block — last resort only**, for the provably-irreparable (active malice, exfiltration), and only
   with receipts proving rectification was attempted and impossible. Denial becomes an *earned
   exception*, never the default response.

This is the same law the ecology runs on: a failing lane gets investigated and re-dispatched bounded,
not banned; a stale lock gets healed by doctrine, not punished. The product should embody the house
style: **repair-forward.**

## Status

DESIGN DIRECTION ONLY (not implemented; no per-rule mode exists in the engine today — verified
2026-10-12). Current live posture is the measuring phase: report_only + receipts + never_intercept +
auto-pin. Enforcement returns as graduation, not as a blanket flip.
