# Test fixtures

| Path | Purpose |
|---|---|
| `signing/release-signed-by-untrusted-key.tar.gz(.sigstore.json)` | Artifact correctly signed with Cosign by a key that the default policy does **not** trust; used to test untrusted-signer rejection |
| `signing/untrusted-signer.pub` | Public half of that key (its private key was destroyed) |
| `osv/synthetic-severity-cases.json` | **Synthetic** osv-scanner-shaped output with fake advisory IDs, used only to test severity fallbacks (label-only, no severity). Not real vulnerability data |

Most tests generate keys, signatures and provenance on the fly in temporary directories.
