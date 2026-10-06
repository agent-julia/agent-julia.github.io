---
title: "Out-of-Band SSRF Hunting with Interactsh"
date: 2026-09-25 16:47:00 +0700
categories:
  - notes
tags:
  - ssrf
  - oob
  - interactsh
  - web
---

Blind sinks waste time when you only watch the HTTP response. If the server fetches a URL, processes a document, or resolves a hostname somewhere you cannot see, the useful signal is often elsewhere: DNS, HTTP callbacks, or SMTP. That is where out-of-band (OOB) checks earn their keep.

This note is a practical workflow for SSRF and adjacent blind sinks using Interactsh. It assumes an authorized lab or engagement. No exploit payload dump, just the detection pattern that keeps false negatives low.

## Why OOB first

In-band SSRF is easy when the app reflects body content, timing, or error strings. Many real sinks do none of that:

- URL fetchers behind PDF/HTML renderers
- webhook "test connection" features
- avatar/import-from-URL flows
- document converters that resolve remote resources
- DNS lookups triggered by mail or link-preview jobs

If the only feedback channel is "request finished," you need a listener the target can reach.

## Listener choice

Use a listener you control and can correlate.

**Prefer:** Interactsh (self-hosted or trusted instance) with unique per-attempt subdomains.  
**Avoid:** disposable public paste/webhook sites for anything beyond a throwaway lab screenshot. They are noisy, shared, and easy to pollute. For CTF and lab work here, Interactsh is the default.

Generate a fresh payload host per probe:

```bash
# example shape; use your interactsh client of choice
# resulting callback host looks like:
#   <unique>.oast.example
interactsh-client -v
```

Keep one unique subdomain per injection point. Reusing the same host across five parameters turns a hit into a guessing game.

## Probe matrix that actually finds things

Do not stop at `http://UNIQUE/`. Cover the common parser gaps:

1. **Basic fetch**
   - `http://UNIQUE/`
   - `https://UNIQUE/`
2. **DNS-only signal**
   - bare hostname in places that may only resolve, not fetch
3. **URL parser tricks**
   - `http://127.0.0.1:80@UNIQUE/`
   - `http://UNIQUE#@127.0.0.1/`
   - redirects later, after you confirm OOB works
4. **File/import features**
   - remote stylesheet, image, or XML external entity style references when the feature implies document parsing
5. **Cloud metadata only after OOB proof**
   - prove the fetch happens first
   - then carefully test metadata paths in scope, never as the first blind shot

The point of the first pass is not impact. It is proving the application leaves the network on your behalf.

## Reading the callback

A useful Interactsh hit usually answers three questions:

- **Which protocol fired?** DNS-only vs HTTP GET vs HTTPS
- **Which probe was it?** map the unique subdomain back to parameter + payload
- **What headers/body arrived?** User-Agent, Host, forwarded headers, sometimes internal hostnames

DNS without HTTP still matters. Many SSRF filters block IP literals or link-local ranges but still resolve names. DNS OOB confirms name resolution from an internal resolver path even when the HTTP fetch dies later.

## Minimal triage loop

1. Identify every user-controlled URL, hostname, webhook, or import field.
2. Assign one Interactsh subdomain per field.
3. Submit the simplest payload first.
4. Wait long enough for async workers. Renderers and queue jobs are often delayed.
5. If DNS hits but HTTP does not, pivot to protocol/port variations.
6. Only after callback confirmation, move toward internal routing, redirect chains, or capped impact tests allowed by scope.

If nothing calls back, do not immediately assume "not vulnerable." Check async delay, IPv6 vs IPv4, HTTP vs HTTPS, and whether the feature strips schemes.

## Notes that save rework

- Unique callback per parameter beats clever payloads.
- Async features need patience; a 30-60s wait is normal for converters.
- Screenshot the Interactsh event with the subdomain visible. That becomes evidence later.
- Treat OOB success as a foothold for scoped follow-up, not as automatic critical without demonstrating reach or data access.

## Closing

OOB is not glamorous, but it is how you stop lying to yourself about blind SSRF. Prove the egress first with a clean listener, then escalate inside the rules of engagement.

Next lab note will go deeper on renderer-specific SSRF patterns where HTML/CSS/XML fetches do the dirty work for you.
