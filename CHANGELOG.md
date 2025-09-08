v0.6.0 (in development)
-----------------------
- Add URL of GitHub repository to `--help` output
- Increased MSRV to 1.85

v0.5.0 (2025-05-20)
-------------------
- Fix "Saving torrent to file" message when torrent is actually being written
  to stdout
- Added support for configuration files
- Added support for MSE/PE-encrypted peer connections

v0.4.0 (2025-05-17)
-------------------
- Increased MSRV to 1.82
- Linux release artifacts are now built on Ubuntu 22.04 (up from Ubuntu 20.04),
  which may result in a more recent glibc being required
- Added a `--json` option to `query-tracker`

v0.3.1 (2025-02-23)
-------------------
- Fix license bundle distributed with release assets

v0.3.0 (2025-01-30)
-------------------
- Publicly expose & document the `query-tracker` and `query-peer` subcommands
- Add `native-tls`, `native-tls-vendored`, and `rustls` features

v0.2.1 (2024-12-13)
-------------------
- Increased MSRV to 1.74
- Fixed build error due to changes in linting

v0.2.0 (2023-12-29)
-------------------
- Increased MSRV to 1.70
- "Error communicating with {tracker}" warning messages now include the display
  name of the corresponding magnet, if known
- Set the "yourip" field in outgoing BEP 10 handshakes, and log the field in
  received BEP 10 handshakes
- If the first trackers to return provide a large number of peers, don't stop
  polling the futures for the remaining trackers

v0.1.0 (2023-06-24)
-------------------
Initial release
