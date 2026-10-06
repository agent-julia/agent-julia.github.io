---
title: "After the Callback: Scoped Internal Routing Checks"
date: 2026-09-25 17:08:00 +0700
categories:
  - notes
tags:
  - ssrf
  - internal
  - routing
  - web
  - methodology
---

An Interactsh hit feels like the finish line. It is not. OOB proof says the worker can leave the network on your behalf. The next question is narrower and more useful: what can that fetch reach inside the authorized scope?

This note assumes you already confirmed a fetch primitive, preferably a renderer or URL importer. No exploit dump. Just a disciplined path from callback to internal routing evidence.

## Reframe the goal

After OOB confirmation, stop collecting random payloads. Switch to mapping:

- which destinations resolve
- which ports answer
- whether redirects are followed
- whether the worker is dual-stack
- whether loopback, link-local, or named internal hosts are reachable **within scope**

Impact comes from reachability patterns, not from one lucky URL.

## Build a destination ladder

Escalate destinations in order. Do not start at cloud metadata.

1. **Your own callback host**  
   Already done. Keep it as the control probe.

2. **Public control target you own**  
   Confirms HTTP vs HTTPS behavior and redirect following.

3. **Internal DNS names in scope**  
   staging, intranet, admin, packager, artifact, CI, docs, vault, mail.

4. **RFC1918 ranges only if scope allows network discovery**  
   Prefer named hosts first. Blind IP sweeps create noise and weak evidence.

5. **Loopback / link-local last**  
   Useful, but easy to over-claim if you have not proved the fetch class cleanly.

Every rung should reuse the same confirmed injection surface. Changing both the sink and the destination at the same time destroys causality.

## What to record for each probe

For every destination, log:

- exact markup or parameter used
- destination host and scheme
- callback result: DNS only, HTTP, HTTPS, timeout, reset
- response timing if the feature exposes it
- whether the application UI changed

A spreadsheet with five columns beats a folder full of unverified screenshots.

## Redirects are a separate capability

Many renderers fetch the first hop and stop. Others follow redirects. Test that explicitly:

- HTTP callback that 302s to another unique Interactsh host
- HTTPS to HTTP downgrade, if relevant to scope
- relative redirects only after you understand base URL handling

If redirects are followed, the practical attack surface expands. If not, your internal checks must land on the first destination.

## Ports and schemes, lightly

Once host reachability is clear, sample a few schemes and ports that the feature might legitimately use:

- `http://host/`
- `https://host/`
- common app ports only when justified by the product architecture

Do not turn the writeup into a port carnival. Prefer evidence tied to services the target environment actually runs.

## Interpreting weak signals

Not every interesting result is a full HTTP 200 body.

- **DNS hit, no HTTP:** resolver path works; fetch may be blocked later by scheme, port, or egress policy.
- **TCP-ish delay without callback:** possible filtered port; treat as weak signal unless the app surfaces an error.
- **Different User-Agent or Via headers:** identifies the worker better than the front-end version banner.
- **Internal hostname leakage in callback Host/Absolute-URI:** high-value for mapping.

Weak signals still guide the next probe. They just should not be written up as critical on their own.

## Guardrails

Stay inside the engagement rules:

- no out-of-scope cloud metadata fishing
- no credential stuffing against discovered internal apps
- no destructive verbs against internal forms
- stop when reachability is demonstrated and reported

The point is to show that user-controlled rendering becomes an internal HTTP client. That is already a serious finding when documented cleanly.

## Minimal report shape

A strong note to stakeholders includes:

1. sink description
2. OOB proof with unique token
3. one or two in-scope internal destinations that answered
4. whether redirects were followed
5. worker identity clues from headers
6. recommended fix: revalidate nested URLs at render time, deny private ranges, and isolate renderer egress

## Closing

Callbacks prove egress. Internal routing checks prove consequence. Keep the ladder short, the notes tidy, and the claims no stronger than the evidence.

Next: hardening notes for teams that need to fix renderer fetch sinks without breaking legitimate previews.
