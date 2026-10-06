---
title: "Hardening Renderer Fetch Sinks: Controls You Can Verify"
date: 2026-09-26 10:42:00 +0700
categories:
  - notes
tags:
  - ssrf
  - hardening
  - egress
  - web
  - methodology
---

The previous note ended on a comfortable line: revalidate nested URLs, deny private ranges, isolate renderer egress. Those are three different controls, they fail in different ways, and two of them are routinely deployed in a form that does not work. This note is about building them so you can prove they hold.

The recurring mistake is treating the blocklist as the control. A string check on the URL is not egress control. It is input hygiene, and it loses to DNS rebinding, decimal-encoded IPs, and redirects unless something deeper stops the packet.

## First, find every sink

You cannot harden what you have not enumerated. Renderers hide in places that do not look like HTTP clients.

```bash
# Python: anything that fetches a URL
grep -rn --include='*.py' -E 'requests\.(get|post)|urlopen|httpx\.|aiohttp' .
# Node
grep -rn --include='*.js' --include='*.ts' -E 'axios|fetch\(|got\(|node-fetch|undici' .
# headless browsers and PDF/HTML renderers
grep -rn -E 'puppeteer|playwright|wkhtmltopdf|weasyprint|prince|cobalt|chromium' .
```

Then confirm the interesting one actually fetches, from the outside, with a callback you control:

```bash
interactsh-client -v
# paste the returned URL into the HTML importer, watch the DNS/HTTP hit
```

If it callbacks, you have a sink. Write down its process name and its network namespace, because the fix lives at that level.

## Control 1: resolve, validate, then pin

The reason URL string checks fail is time-of-check to time-of-use. You validate the hostname, then the renderer resolves it again and gets a different answer. The fix is to resolve once, judge the address, and then make the request to that exact address.

```python
import ipaddress, socket, urllib.parse

def _is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )

def resolve_pinned(url: str):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")
    host = parts.hostname
    infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                              proto=socket.IPPROTO_TCP)
    addrs = {ipaddress.ip_address(i[4][0]) for i in infos}
    if not addrs or any(not _is_public(a) for a in addrs):
        raise ValueError("destination not allowed")
    return sorted(addrs)[0]  # pin this exact IP for the actual fetch
```

The important property is that the validation and the connection use the same answer. If you validate with `getaddrinfo` and then hand the hostname to `requests`, you have reintroduced the race.

Verify it rejects the classic bypasses, not just `127.0.0.1`:

```bash
python3 - <<'PY'
from harden import resolve_pinned
for u in ["http://127.0.0.1/", "http://2130706433/", "http://[::1]/",
          "http://169.254.169.254/latest/meta-data/", "http://0x7f000001/"]:
    try:
        print(u, "->", resolve_pinned(u))
    except Exception as e:
        print(u, "REJECT", type(e).__name__)
PY
```

Decimal, hex, and IPv6 loopback should all land on REJECT because they resolve to addresses in the blocked set, not because a regex caught the string.

## Control 2: egress policy, not input policy

Even a correct resolver is application code, and application code has bugs. The control that survives a bug is the one that drops the packet after the bug decides to send it.

On the renderer host, default-deny outbound and allow only what the renderer legitimately needs:

```bash
# nftables: allow loopback, established, DNS, and the one public range it needs
nft add table inet renderer
nft add chain inet renderer out '{ type filter hook output priority 0 ; policy drop ; }'
nft add rule inet renderer out oif lo accept
nft add rule inet renderer out ct state established,related accept
nft add rule inet renderer out udp dport 53 accept
nft add rule inet renderer out ip daddr 203.0.113.0/24 tcp dport {80,443} accept
```

Then prove private ranges are actually dead from that host, which is the test most teams skip:

```bash
curl -sS -m 3 http://169.254.169.254/ ; echo "exit=$?"
curl -sS -m 3 http://10.0.0.1/ ; echo "exit=$?"
```

You want timeouts or `Network unreachable`, not a banner. If you get a banner, the renderer is on a network where that host is reachable and your policy is not the boundary you think it is.

If you cannot touch the host firewall, put an egress proxy in front and enforce the allowlist there:

```bash
# enforce at the proxy, then make the renderer use it
export HTTPS_PROXY=http://127.0.0.1:8443
curl -sS -x http://127.0.0.1:8443 http://10.0.0.1/ ; echo "exit=$?"
```

## Control 3: isolation

The strongest control is that the renderer has no route to the sensitive network at all. A separate namespace with a single NATed path gives you exactly that:

```bash
ip netns add render
ip link add veth-render type veth peer name veth-host
ip link set veth-render netns render
ip netns exec render ip addr add 10.200.0.2/30 dev veth-render
ip netns exec render ip link set veth-render up
ip netns exec render ip route add default via 10.200.0.1
# host side NATs only to the internet, never to internal ranges
```

Verify the namespace cannot see the internal network while the host still can:

```bash
ip netns exec render curl -sS -m 3 http://10.0.0.1/ ; echo "ns_exit=$?"
curl -sS -m 3 http://10.0.0.1/ ; echo "host_exit=$?"
```

Different exit codes for the same destination is the whole point. Isolation is not a config line, it is a topology that makes the internal range unroutable from the sink.

## Redirects need the same controls applied twice

A renderer that follows redirects re-enters the resolver on the second hop. If your pinning only happens on the initial URL, a 302 to `http://169.254.169.254/` walks right past it.

```bash
# expect the redirect target to be revalidated, not silently followed
curl -sS -L -m 5 -o /dev/null -w '%{url_effective} %{http_code}\n' \
  'http://your-renderer/import?url=https://httpbin.org/redirect-to?url=http://169.254.169.254/'
```

The correct outcome is a blocked second hop, not a 200 from the metadata address. Test it explicitly; redirect following is a separate capability and it needs its own test case.

## What a verifiable control looks like

You are done when you can hand someone three commands and they get the same result you did:

```bash
# 1. input layer rejects the encoded loopbacks
python3 -c 'from harden import resolve_pinned; resolve_pinned("http://2130706433/")' 2>&1 | tail -1
# 2. egress layer drops the metadata address
curl -sS -m 3 http://169.254.169.254/ ; echo $?
# 3. isolation layer has no route at all
ip netns exec render curl -sS -m 3 http://10.0.0.1/ ; echo $?
```

Three layers, three tests, three failure modes covered independently. Blocklists are none of them. The point of the exercise is that when someone asks "is the renderer safe," the answer is a command anyone can run, not a claim in a ticket.