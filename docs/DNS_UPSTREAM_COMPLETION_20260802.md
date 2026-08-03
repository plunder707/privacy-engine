# DNS Upstream Completion Upgrade

Date: 2026-08-02

## Verdict

The DNS filter no longer treats an HTTP connection close as the end of a DoH
response. It now uses HTTP/1 framing, validates the DNS reply, and records a
completed response only after the framed body has arrived.

The portable profile fails closed when DoH fails. The mirrored-WSL operator
profile may fall back to UDP, but the downgrade is explicit in configuration
and visible in metrics.

## Implementation

- `doh_request_over_io` uses Hyper HTTP/1 framing, accepts Content-Length and
  chunked bodies on persistent connections, and caps DNS bodies at the DNS
  packet limit.
- Replies must be HTTP 200 with `application/dns-message`, and their DNS ID and
  question must match the request.
- Each upstream query has a two-second deadline.
- `dns_doh_failure_mode` is `fail_closed` or `fallback_udp`.
- A bounded semaphore limits upstream work. Local block decisions occur before
  the semaphore, so a stalled upstream cannot delay an immediate NXDOMAIN.
- UDP fallback uses a socket per query, avoiding reply races between concurrent
  requests.

## Profiles

- `configs/easylist.local.json`: portable `127.0.0.1:5353`, strict DoH.
- `configs/easylist.wsl-mirrored.json`: operator-specific `127.0.0.2:53`,
  measured UDP fallback for mirrored WSL recovery.

Neither profile changes Windows DNS, proxy, NordVPN, or Tailscale settings.

## Verification

Automated verification:

- Rustfmt passed.
- Strict Clippy passed.
- 234 tests passed.
- Release build passed.
- Fixtures cover Content-Length and chunked keep-alive DoH, invalid content
  type, strict failure, measured UDP fallback, and local blocking while an
  upstream request is stalled.

Isolated canary, with production left running on port 18081:

- Candidate proxy: `127.0.0.1:18082`
- Candidate DNS: `127.0.0.1:15353`
- Candidate dashboard: `127.0.0.1:9091`
- `example.com`: valid DoH answer
- `doubleclick.net`: immediate policy NXDOMAIN
- `www.wikipedia.org`: HTTP 200, 122,088 of 122,088 bytes in 0.102 seconds
- Metrics: 1 DoH query, 1 completed DNS response, 0 DoH failures, 0 UDP
  fallbacks, 0 upstream failures, 0 saturation drops
- Response metrics: 1 completed flush, 0 incomplete responses

The candidate was stopped after the canary. The production PID and uptime were
unchanged during the test.

## Remaining Boundary

`fallback_udp` is a confidentiality downgrade and belongs only in an explicit
operator profile. It must never become the portable default. The dashboard now
makes fallback and failure counts visible, but Windows resolver promotion is
still an operator action described in `docs/WINDOWS_WSL_NETWORKING.md`.
