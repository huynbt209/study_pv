# study_pv

Password-protected GitHub Pages build of a private study site. `docs/index.html` holds the whole site
gzipped and encrypted with AES-256-GCM behind a password form; the plaintext sources are not in this repo.

## Rebuild

Copy the plaintext site (index.html + data .js files) from the private repo into this folder, then run
`node build.mjs`. It asks for the password and writes `docs/index.html`; commit and push only `docs/`.
The password is never stored in the repo or in the output; in CI pass it as `STUDY_PASSWORD` from a secret.

On the deployed page, "Remember on this device" keeps the derived key in localStorage; open the page
with `?lock` to forget it. Every build uses a new salt, so remembered devices must log in again.
