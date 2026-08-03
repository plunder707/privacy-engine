# HTTP/1.1 Rewrite Response Completion Fix

## Verdict

The rewritten-response stall was caused by a missing client flush boundary.
`write_all` completed inside the TLS stream, but a keep-alive upstream could
leave the final TLS records buffered indefinitely. The relay then waited for
more upstream data while the client waited for the remaining response bytes.

This was independent of DNS, Tailscale, VPN state, chunked framing, and body
size. The failure reproduced on `www.wikipedia.org` with identity encoding:

| Build | Advertised | Received | Result |
| --- | ---: | ---: | --- |
| Previous live build | 122,088 | 98,304 | timed out after 10s |
| Candidate | 122,088 | 122,088 | completed in 0.10s |

The candidate also completed three repeated Wikipedia probes, a 609 KB
Content-Length response, a 1.3 MB rewritten response, and the compressed
Wikipedia response. All advertised Content-Length values matched bytes read.

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

## Rollout

The candidate was validated on isolated proxy/dashboard ports `18082/9091`.
The existing `18081/9090` process was not restarted or modified. Promotion
should use the normal restart path only after the branch is reviewed and the
existing dirty runtime configuration is reconciled separately.
