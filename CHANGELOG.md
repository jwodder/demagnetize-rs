v0.4.0 (in development)
-----------------------
- Increased MSRV to 1.81

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
