# Verifying a release

Every release (issue #49) — both the binary archives and the container
image (issue #51) — is signed keylessly via [Sigstore/cosign](https://www.sigstore.dev/) —
using this repo's own GitHub Actions identity to sign, not a private key a
maintainer generated and could lose, leak, or have to rotate. Verifying a
download anchors trust in two specific values below, not just "run this
command and see if it says OK."

## Binary releases

### What's published with each release

- `spidercob-gateway_<version>_<os>_<arch>.tar.gz` — one archive per
  platform (`linux`/`darwin` × `amd64`/`arm64`), each containing the
  `spidercob` binary, `README.md`, and `LICENSE`.
- `checksums.txt` — SHA-256 of every archive above.
- `checksums.txt.bundle` — the cosign signature bundle covering
  `checksums.txt` (and therefore, transitively, every archive whose hash
  it contains).

### Verify

1. Install [cosign](https://docs.sigstore.dev/system_config/installation/) (`brew install cosign`, or see the link).
2. Download `checksums.txt`, `checksums.txt.bundle`, and the archive for
   your platform from the [Releases page](https://github.com/SpiderCob/spidercob-gateway/releases).
3. Verify the signature bundle:

   ```bash
   cosign verify-blob \
     --bundle checksums.txt.bundle \
     --certificate-identity-regexp "^https://github\.com/SpiderCob/spidercob-gateway/" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   ```

   The two `--certificate-*` values are what actually anchor the trust
   here — they assert "this was signed by a GitHub Actions workflow run
   belonging to `SpiderCob/spidercob-gateway`, using Sigstore's public
   OIDC issuer," not just "some signature verifies." A verification
   command without them would accept a signature from *any* keyless
   signer, not specifically this project's CI.

4. Verify your downloaded archive's checksum matches the now-trusted
   `checksums.txt`:

   ```bash
   shasum -a 256 -c checksums.txt --ignore-missing   # macOS
   sha256sum -c checksums.txt --ignore-missing        # Linux
   ```

If both steps succeed, the archive you downloaded is byte-for-byte what
this project's own CI built and published for that release — not a fork,
not a tampered mirror, not a supply-chain substitution.

## Container image

Every `v*` tag also publishes a signed, multi-architecture (`linux/amd64`,
`linux/arm64`) image to `ghcr.io/spidercob/spidercob-gateway`, tagged both
with the exact release version and a floating `latest`. The signature
covers the image's content-addressed **digest**, not either mutable tag —
so it stays valid even after `latest` moves to point at a newer release.

### Verify

1. Install [cosign](https://docs.sigstore.dev/system_config/installation/), same as above.
2. Resolve the digest for the tag you're about to run:

   ```bash
   docker pull ghcr.io/spidercob/spidercob-gateway:v0.1.0
   digest=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/spidercob/spidercob-gateway:v0.1.0)
   ```

3. Verify it — same two `--certificate-*` values as the binaries above,
   because it's the same identity (this repo's own CI) signing both:

   ```bash
   cosign verify "$digest" \
     --certificate-identity-regexp "^https://github\.com/SpiderCob/spidercob-gateway/" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

`cosign verify` (for an OCI image, addressed by digest) is the sibling of
`cosign verify-blob` (for a plain file) used for the binary archives
above — same trust anchor, different artifact shape.

## Why keyless, not a GPG-signed checksum

The older convention — a maintainer's personal GPG key signs the
checksums file — means trusting that key was generated, stored, and
rotated correctly, and that you've correctly imported the *right* public
key in the first place (itself a bootstrapping trust problem). Keyless
signing replaces "trust a person's key" with "trust GitHub's own OIDC
issuer plus this specific repository" — no private key exists for a
solo maintainer to lose or leak, and the certificate identity above is
independently checkable against the workflow run that produced it (every
signature is logged to Sigstore's public, append-only [Rekor](https://docs.sigstore.dev/logging/overview/)
transparency log).
