# kotoba-lang/org-ietf-tls

**A TLS 1.3 client — [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) —
in portable `.cljc`, with every cryptographic primitive injected.**

It completes a real handshake against a real server and moves application data.
It authenticates the peer **by public-key pin**, not by chain validation to a
trust anchor. Read *What you must not assume* before using it for anything.

```clojure
(require '[tls.client :as client]
         '[tls.transport.jvm :as tp]
         '[tls.result :as r])

(let [t (tp/socket-transport "kotobase.net" 443 {:timeout-ms 15000})
      conn (r/val (client/handshake provider t
                    {:server-name "kotobase.net"
                     :pin-spki-sha256 "50602ad366823fcf5274a7c917baa4fd24b9de4fd15635ff501177c83d05473e"}))]
  (client/write! conn (tls.codec/ascii "GET /llms.txt HTTP/1.1\r\nHost: kotobase.net\r\nConnection: close\r\n\r\n"))
  (r/val (client/read! conn))     ;=> {:tls/content [72 84 84 80 ...]}
  (client/close! conn))
```

## What actually ran

Two live handshakes, both reproduced by `scripts/` in this repo.

| against | suite | CertificateVerify | result |
|---|---|---|---|
| `openssl s_server` on loopback, Ed25519 certificate, OpenSSL 3.6.3 | `TLS_AES_128_GCM_SHA256` | `ed25519` | handshake, `GET /`, **7 KiB HTTP response**, `close_notify` |
| **`kotobase.net:443`** (Cloudflare), over the public internet | `TLS_AES_128_GCM_SHA256` | `ecdsa_secp256r1_sha256` | handshake, 3-certificate chain, `GET /llms.txt`, **6,391-byte body**, `close_notify` |

Both verified the server's `CertificateVerify` signature over the section 4.4.3
context string and the transcript, verified the server's `Finished`, sent their
own `Finished`, and matched the leaf SPKI against a pin.

The same live path, run with a deliberately wrong pin against the same server,
**refuses**:

```clojure
#:tls{:alert :bad_certificate, :reason :spki-pin-mismatch,
      :expected "aaaa…aaaa",
      :actual   "50602ad366823fcf5274a7c917baa4fd24b9de4fd15635ff501177c83d05473e"}
```

## RFC 8448 is the oracle

A cryptographic implementation checked only against itself is worth nothing.
[RFC 8448](https://www.rfc-editor.org/rfc/rfc8448.html) publishes byte-exact
traces of a complete TLS 1.3 handshake — every intermediate secret, every
serialized `HkdfLabel`, every protected record. Section 3 is reproduced here
**byte for byte**:

- the X25519 shared secret, from the RFC's own private and public keys
- the whole ladder: early → derived → handshake → `c/s hs traffic` → derived →
  master → `c/s ap traffic` → `exp master` → `res master`
- the serialized `HkdfLabel` for `derived`, `c hs traffic`, `key`, `iv`,
  `finished` — checked *separately* from their outputs, because a wrong info
  block and a wrong PRK produce the same wrong answer and only this
  distinguishes them
- both directions' handshake and application traffic keys and IVs
- **all six protected records**, decrypted *and* re-encrypted to the identical
  ciphertext (AES-GCM is deterministic given key and nonce, so this is a real
  equality, not a round-trip through our own code)
- both `Finished` messages' `finished_key` and `verify_data`
- the resumption PSK

The vectors are **not transcribed by hand**. `scripts/extract_rfc8448.cljs`
parses them out of the RFC's own text; each block in the RFC declares its own
octet count and the extractor refuses to emit one that does not reach it
exactly. The fixture records the SHA-256 of the input it came from
(`6564d137…`), so a reader can re-fetch and re-derive.

## What you must not assume

- **This is not a general-purpose TLS client.** It has one job: open a
  connection to a host whose key you already know.
- **There is no chain validation.** No root store, no path building, no name
  constraints, no CRL, no OCSP, no expiry check, **no hostname verification
  against the certificate**. `handshake` refuses to proceed unless you pass
  `:pin-spki-sha256`, a `:verify-chain` function, or the explicit
  `:insecure-skip-peer-auth` — there is no default, because a client that
  authenticates nothing and returns success is worse than one that fails.
  `tls.cert` is where real chain handling belongs.
- **No HelloRetryRequest.** One X25519 key share. If the server wants another
  group the handshake refuses and names it. Servers that require P-256 are
  unreachable.
- **No resumption, no 0-RTT, no PSK, no client certificates, no ALPN
  negotiation, no KeyUpdate.** A peer `KeyUpdate` is refused rather than
  ignored — ignoring one desynchronises the keys silently.
- **Only `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`.**
  `TLS_AES_256_GCM_SHA384` is not offered: it needs SHA-384, and offering a
  suite the provider may not carry is negotiating into a handshake that cannot
  finish. Which of the two is actually offered is *computed from the provider*
  (`tls.suite/negotiable`), not declared.
- **`tls.client/spki-of` is a hand-rolled DER walk and is a stopgap.** It finds
  the SubjectPublicKeyInfo structurally. It is marked as such in the source and
  belongs in `tls.cert` on top of `kotoba-lang/org-ietf-x509`.
- **Timing.** The protocol layer is not written to be constant-time beyond the
  two comparisons that must be (`verify_data`, AEAD tags — and the latter is
  the provider's). Byte vectors of boxed integers are not a constant-time
  representation, and nothing here claims otherwise.
- **`test/tls/jdk_provider.clj` is a test-scope stand-in**, not the shipped
  provider. `src/tls/provider/jvm.clj` is the real one.

## Layout

| namespace | RFC 8446 | what it owns |
|---|---|---|
| `tls.result` | — | `[:ok v]` / `[:error e]`. Nothing throws; every error carries the alert a peer would receive |
| `tls.codec` | §3 | the presentation language: cursor-based reads, `opaque x<lo..hi>` with its bounds, `u64` written with division so a 64-bit sequence number does not round |
| `tls.alert` | §6 | alert descriptions; `close_notify`/`user_canceled` may be warnings, everything else is forced fatal |
| `tls.transcript` | §4.4.1 | the message-level transcript (headers included), forkable at the four points TLS needs |
| `tls.schedule` | §7, RFC 5869 | HKDF, `HkdfLabel`, `Derive-Secret`, the ladder, traffic keys, `Finished`, KeyUpdate, resumption, exporter |
| `tls.record` | §5 | TLSPlaintext / TLSInnerPlaintext / TLSCiphertext, the §5.3 nonce, padding, size bounds |
| `tls.extension` | §4.2, RFC 6066 | extension framing; unknown extensions round-trip byte-exactly; duplicates refused |
| `tls.handshake` | §4 | message framing and bodies; HelloRetryRequest detection; the §4.1.3 client checks |
| `tls.suite` | App. B.4 | suite geometry bound to the provider's AEAD |
| `tls.client` | — | the driver: handshake, `write!`, `read!`, `close!` |
| `tls.transport.jvm` | — | a TCP socket. Two functions, `:send` and `:recv` |

Bytes everywhere are `vector<int 0..255>`, the representation
`kotoba-lang/bytes`, `kotoba-lang/noise` and `kotoba-lang/org-ietf-asn1`
already use — so the protocol layer needs no reader conditional.

## The provider seam

Nothing in `src/` implements a cipher. The seam is copied deliberately from
`kotoba-lang/noise`, which states the argument: constant-time field arithmetic
and constant-time tag comparison are exactly what a hand-rolled portable port
loses, so those come from an audited implementation while everything that is
pure data-shuffling stays portable and identical on every runtime.

Say the consequence plainly: **on bare metal, where there is no JDK and no npm,
the provider is precisely the part that does not exist.** This library does not
close that gap. It reduces it from *a TLS stack* to *X25519, AES-GCM or
ChaCha20-Poly1305, SHA-256, HMAC, and one signature verify* — which is close to
what `kotoba-lang/aiueos` already has in `x25519.kotoba` and `sha256.kotoba`.

## What was reused rather than rewritten

Searched first (44,192 source files under `orgs/`, plus the west manifest's
4,229 project names and the concept index). There was **no TLS 1.3 protocol
implementation anywhere** — `capability-crypto-tls` is `provider-status:
contract-only`, and `io-storj-node` / `provider-transport` both call the *host's*
TLS 1.2. What did exist and is used or is directly adjacent:

| repo | what it gives |
|---|---|
| `kotoba-lang/noise` | the injected-primitive seam this copies, and its security argument |
| `kotoba-lang/org-nist-sha2` | pure `.cljc` SHA-256 + HMAC — the whole key schedule can run with **no host crypto at all** |
| `kotoba-lang/bytes` | the `vector<int 0..255>` byte contract |
| `kotoba-lang/org-ietf-x509`, `org-ietf-asn1` | RFC 5280 / X.690 — what `tls.cert` will build chain handling on |
| `kotoba-lang/org-ietf-tcp` | RFC 9293 TCP as a pure state machine — the layer below, for when there is no socket |
| `kotoba-lang/org-ietf-ed25519` | Ed25519, for a provider without a JDK |

## Test

```sh
clojure -M:test                   # plain clojure.test

# the counting harness (the :test alias already binds :main-opts, so the
# report alias supplies its own; a :report alias in deps.edn would be tidier)
clojure -Sdeps '{:aliases {:report {:extra-paths ["test"] :main-opts ["-m" "tls.report"]}}}' \
  -M:test:report
```

Last run:

```
Ran 23 tests containing 196 assertions.
0 failures, 0 errors.

RFC8448-SOURCE-SHA256      6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba
RFC8448-BLOCKS-IN-FIXTURE  108
RFC8448-VECTORS-COMPARED   43
REFUSALS-EXERCISED         40
ASSERTIONS                 196 passed, 0 failed, 0 errored
OK
```

`tls.report` (see below for the invocation) exits **3**, not 1, when it could not run its vectors at all — a
suite that could not measure has not found a bug, and reporting one is its own
kind of lie. It refuses to report a pass on zero vectors compared or zero
refusals exercised.

Live runs are `scripts/live_loopback.clj` and `scripts/live_kotobase.clj`; they
are not part of the default suite because they need a network.

Apache-2.0.
