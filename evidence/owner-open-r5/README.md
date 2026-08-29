# Owner-Open R5 reviewed evidence bundles

Only independently reviewed, locally revalidated bundles belong below this
directory. Each bundle is a closed directory containing `manifest.json` and all
bounded textual artifacts declared by that manifest.

Capture-only GitHub Actions artifacts are not copied here unchanged. First
unpack them in an isolated directory, review every raw file, finalize with an
independent review attestation, run
`tools/verify-owner-open-r5-evidence-bundle.py --require-promotable`, and then
open an evidence PR. Never store credentials, bearer tokens, private keys,
mutable links, device secrets or large image binaries here.
