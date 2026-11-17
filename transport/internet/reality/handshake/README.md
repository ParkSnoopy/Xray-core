# Maintained REALITY backend

Snapshot of `github.com/xtls/reality` at
`v0.0.0-20261108101329-4bb46b2afd8b`, integrated into this Xray fork so downstream
builds do not depend on ignored transitive `replace` directives. Upstream
`LICENSE` and `LICENSE-Go` are preserved verbatim.

Changes:
- Accept P-256, P-384, and P-521 target key shares using Go's ECDH implementation.
- Relay one ECDH HelloRetryRequest, validate the second ClientHello, and retain
  the original X25519 authentication identity.
- Reconstruct the retry transcript and preserve compatibility CCS placement.
- Preserve fragmented retry/final ServerHello records and their transcript.
- Reject changed extension contents, presence, and order on retry; bound retry
  and fragmented-hello waits to ten seconds and interrupt them on cancellation.
- Observe target EOF while waiting for the second ClientHello.
- Bind optional ML-DSA verification to the final ServerHello in the Xray client.

Chrome clients without ML-DSA need only a server upgrade. ML-DSA with a retry
requires the updated client too; signature verification is not weakened.
ML-DSA also requires a target handshake flight large enough to carry its
signature; additional curves do not remove that existing camouflage constraint.
The pinned uTLS Firefox fingerprint fails ordinary P-256 TLS with an invalid
server key share. Tests explicitly report that baseline limitation; use Chrome
for P-256 targets. The pinned Chrome fingerprint does not advertise P-521; use
Firefox for P-521 targets. P-384 works with both. Browser group advertisements
are not silently modified. Existing X25519 and X25519MLKEM768 remain supported.

Go API migration: `Config.GetREALITYConfig()` now returns this source snapshot's
`Config` type. Direct Go callers must import
`github.com/xtls/xray-core/transport/internet/reality/handshake` instead of
`github.com/xtls/reality`. Profile configuration and authentication keys retain
their existing format.

Run `go test ./transport/internet/reality/...` for local RAW/XHTTP round trips,
ML-DSA, fragmented hellos, invalid credentials and retry mutations, stalled retry
cleanup, and TLS fallback. Use `-race` to exercise observer cleanup concurrently.
The integration matrix also accepts `XRAY_REALITY_TARGET` and
`XRAY_REALITY_SERVER_NAME` for explicitly selected live-target cases. These
overrides do not force the remote target's curve or record fragmentation; use
the local matrix for controlled curve and fragmentation coverage.
