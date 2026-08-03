# Windows, WSL, VPN, and DNS Operations

This guide separates four independent network controls that are easy to
confuse when the engine runs inside mirrored WSL.

| Layer | Owner | What Privacy Engine Does |
|---|---|---|
| Windows or browser proxy | Windows/browser | Listens on `127.0.0.1:18081`; never enables the setting. |
| WSL resolver | WSL/Windows DNS tunneling | Offers an optional DNS listener; never rewrites `/etc/resolv.conf`. |
| NordVPN | NordVPN on Windows | Uses whatever route and DNS Windows exposes; never starts or changes Nord. |
| Tailscale | Tailscale on Windows | Coexists with it; never starts, authenticates, or selects an exit node. |

## Profiles

Use the portable profile on ordinary Linux, macOS, or non-mirrored WSL:

```bash
./scripts/pe-restart.sh configs/easylist.local.json
```

It binds DNS to `127.0.0.1:5353` and fails closed if DoH fails.

Use the operator profile on this mirrored-WSL installation:

```bash
./scripts/pe-restart.sh configs/easylist.wsl-mirrored.json
```

It binds DNS to `127.0.0.2:53`. Because port 53 is privileged, the restart
helper verifies `CAP_NET_BIND_SERVICE` before stopping a healthy process. This
profile permits UDP fallback, and every fallback is visible in metrics.

## Safe Startup and Verification

The restart helper builds first and leaves the current process running if the
build, JSON validation, or capability check fails. After startup, verify:

```bash
curl -fsS http://127.0.0.1:9090/api/status | jq .
curl -fsS http://127.0.0.1:9090/api/metrics \
  | jq '{dns_query_total,dns_response_completed_total,dns_doh_failure_total,dns_udp_fallback_total,dns_upstream_failure_total,dns_query_saturated_total}'
dig @127.0.0.2 -p 53 example.com A +time=2 +tries=1
dig @127.0.0.2 -p 53 doubleclick.net A +time=2 +tries=1
```

An allowed query must complete. A blocked query must return NXDOMAIN. A rising
`dns_udp_fallback_total` means service is available but encrypted upstream DNS
is failing. A rising `dns_upstream_failure_total` means neither permitted path
completed.

## Windows Proxy

Windows system proxying is optional. Aether and other applications may use the
engine explicitly through `HTTP_PROXY`, `HTTPS_PROXY`, or their own proxy
setting even when Windows `ProxyEnable` is off.

Before enabling a Windows-wide proxy, verify the CA is trusted and test a
browser profile. Cert-pinned applications may need passthrough rules. Disable
the system proxy before stopping the engine or the browser may appear offline.

## Changing NordVPN Servers

Privacy Engine does not pin a NordVPN server or adapter. Changing servers may
temporarily replace routes and DNS servers while existing proxy connections
are still open. Use this sequence:

1. Stop new browser activity.
2. Change the NordVPN server in Windows.
3. Wait for ordinary Windows and WSL DNS to resolve again.
4. Run the direct privacy DNS canary above.
5. Restart Privacy Engine only if its listener or upstream checks fail.

Do not restart Tailscale merely to change NordVPN servers. Both products can
modify Windows routes; changing both at once destroys fault isolation.

## Resolver Promotion and Rollback

Keep WSL on the working Windows DNS-tunneling resolver until the privacy DNS
canary passes repeatedly. Switching `/etc/resolv.conf` to `127.0.0.2` is an
explicit operator action, not part of engine startup.

Before a resolver change, record the current file. Roll back by restoring the
previous Windows-tunneling nameserver and then confirming ordinary resolution.
Never make Privacy Engine startup responsible for editing the resolver file;
otherwise a failed engine start can remove the DNS path needed to repair it.

## Tailscale

An installed or running Windows service does not mean the Tailscale client is
authenticated or connected. Treat its client status as separate from service
status. Privacy Engine needs no Tailscale connection for loopback proxy or DNS
operation.

## Failure Interpretation

- Proxy listener down: browser/application proxy requests fail; direct traffic
  still works unless Windows proxying is enabled.
- Privacy DNS listener down: only clients explicitly using that listener fail.
- DoH failure with WSL profile: UDP fallback keeps DNS available and increments
  telemetry.
- DoH failure with portable strict profile: allowed queries fail closed.
- NordVPN transition: routes or Windows DNS may disappear briefly; do not
  attribute that transient outage to Privacy Engine without a direct canary.
