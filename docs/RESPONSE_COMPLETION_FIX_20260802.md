# HTTP/1.1 Rewrite Response Completion Fix

## Verdict

The rewritten-response stall was caused by a missing client flush boundary.
`write_all` completed inside the TLS stream, but a keep-alive upstream could
leave the final TLS records buffered indefinitely. The relay then waited for
more upstream data while the client waited for the remaining response bytes.

This was independent of DNS, Tailscale, and VPN state. The original public
reproduction was `www.wikipedia.org` with identity encoding:

| Build | Advertised | Received | Result |
| --- | ---: | ---: | --- |
| Previous live build | 122,088 | 98,304 | timed out after 10s |
| Candidate | 122,088 | 122,088 | completed in 0.10s |

The candidate also completed three repeated Wikipedia probes, a 609 KB
Content-Length response, a 1.3 MB rewritten response, and the compressed
Wikipedia response. Those cases are regression controls, not independent proof
of the repair, because they already completed with the previous build.

The causal evidence is an end-to-end size sweep against a local HTTPS origin.
The origin served Content-Length HTML, kept the upstream connection open, and
varied the source body from 1 KiB through just over 2 MiB. The request traversed
the real proxy and body-rewrite path; rewritten bodies gained the 1,727-byte
anti-overlay shim.

| Build | Passed | Failed | Result |
| --- | ---: | ---: | --- |
| Previous deployed binary | 155 / 188 | 33 | failures timed out with partial bodies |
| Candidate | 188 / 188 | 0 | every advertised length was delivered |

The old failures spanned source bodies from 115,712 through 1,983,488 bytes and
several partial-delivery plateaus. The defect was therefore size- and
timing-sensitive, not Wikipedia-specific. The missing response-boundary flush
explains the broader failure class; the candidate eliminated it across the
entire sweep.

## Runtime Contract

Buffered Content-Length and chunked responses now use one completion path:

1. Verify that any advertised Content-Length equals the completed body length.
2. Write the rewritten headers, body, and any already-buffered overflow.
3. Flush the client stream at the response boundary.
4. Record completion only after the flush succeeds.
5. Return an error and record an incomplete response if framing, writing, or flushing fails.

`response_flush_completed_total` means the completed response crossed the
runtime's `AsyncWrite::flush` boundary. It does not claim application-level
acknowledgement by the remote client.

The Content-Length validation is defense in depth. Rewriting normally computes
the header immediately before this function, so the validation primarily
protects future call sites and catches an internal framing regression. The
flush boundary is the delivery repair.

## Observability

The metrics API, dashboard, and per-host receipts now expose:

- `body_rewrite_bytes_injected_total`
- `response_flush_completed_total`
- `response_flush_failed_total`
- `response_incomplete_total`
- `response_content_length_mismatch_total`

This separates content transformation from response delivery. A rewrite that
adds the anti-overlay shim no longer appears to be a zero-effect operation.

## Regression Coverage

The keep-alive fixture uses a writer that withholds bytes until `flush` is
called while the upstream remains open. It covers:

- 120 KB Content-Length HTML
- 120 KB chunked HTML
- 600 KB Content-Length HTML
- explicit flush failure and incomplete-response accounting
- Content-Length mismatch rejection before any client bytes are emitted

The full suite passes with 227 tests. Strict Clippy and the release build also
pass.

The sweep is reproducible with `scripts/response_size_sweep.py`. Local evidence
is bound to the exact binaries and source state:

| Artifact | SHA-256 |
| --- | --- |
| Previous results JSONL | `8ba63d27916c130f0a0c8290986660a75f282fca7a7867763eacb2c54d4f8188` |
| Candidate results JSONL | `fa50ac66f9dfe8f56168f3089490dfdaf5c490dbe701e443ee49a5a046b2d56c` |
| Previous binary | `898713cbb0c4dbd0bbf264034ec28c8e0cf347f9142395b7f8034d888a06431f` |
| Candidate binary | `26c03d7393e1b38c246d8dfb400dd358ad46cd3a08619fde4a10c8825ab81283` |

The raw JSONL files remain local and gitignored. Their manifests record binary
identity, Git state, fixture settings, and per-run hashes.

## Rollout

The candidate was first validated on isolated proxy ports, then promoted to
`fix/request-stream-inspection`. The live service was restarted from commit
`6151e89` with binary SHA-256
`f807d221c22f57a496ef4b0ad3625c77c7868d02070ee767f00bf3f926c4453d`.

The post-promotion `www.wikipedia.org` identity-encoding canary completed in
0.096 seconds with 122,088 advertised and received bytes. Runtime telemetry
recorded one completed flush, 1,727 injected bytes, and zero flush failures,
incomplete responses, or Content-Length mismatches. A Windows client also
completed an HTTPS request through `127.0.0.1:18081`.

The tracked local configuration now preserves the mirrored-WSL DNS binding
required on this machine (`127.0.0.2:53`), the DoH upstream, and explicit
HTTP/1.1 rewrite behavior. Promotion must retain the existing CA and runtime
state directories. Rollback is the previous binary and configuration; no CA,
receipt, filter-list, or pin database migration is required.

The restart helper now builds before stopping the current process, checks the
port-53 file capability before disruption, detaches the service into a new
session, and verifies the proxy, dashboard, and DNS listeners before reporting
success.
