# kotoba-lang/org-ietf-tls

**[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) TLS 1.3 — a client**,
portable `.cljc`, with cryptographic primitives injected through a provider
seam.

This repository exists because `kotoba-lang/aiueos` ADR-0041 measured the gap
and found nothing to fill it: *"TLS 1.3 client and chain validation — no
implementation anywhere in the workspace"*. Every layer a cloud-premised OS
needs above it — an HTTP client, kotobase blocks, murakumo inference — is
blocked on this one.

## Boundary

- **Protocol logic is pure.** Bytes in, decisions and bytes out. Nothing here
  opens a socket, reads a clock, or reaches a file.
- **Primitives are injected**, following `kotoba-lang/noise`'s provider layout
  (`src/noise/provider/{jvm.clj,noble.cljs,node.cljs}`). The JVM provider is
  what makes this usable today; aiueos's native `x25519.kotoba` / `sha256.kotoba`
  are what the same seam is meant to accept later.
- **Errors are returned, not thrown** — `[:result T E]`-shaped values, per this
  workspace's language rules. A refusal names itself.

## Status

Scaffold. Nothing is implemented yet; this file will say what is, and what is
not, as it lands. Until then, take the absence of a claim as an absence of a
capability.
