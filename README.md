[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![CI Status](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml/badge.svg)](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml)
[![codecov.io](https://codecov.io/gh/jwodder/demagnetize-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/jwodder/demagnetize-rs)
[![Minimum Supported Rust Version](https://img.shields.io/badge/MSRV-1.82-orange)](https://www.rust-lang.org)
[![MIT License](https://img.shields.io/github/license/jwodder/demagnetize-rs.svg)](https://opensource.org/licenses/MIT)

[GitHub](https://github.com/jwodder/demagnetize-rs) | [crates.io](https://crates.io/crates/demagnetize) | [Issues](https://github.com/jwodder/demagnetize-rs/issues) | [Changelog](https://github.com/jwodder/demagnetize-rs/blob/master/CHANGELOG.md)

`demagnetize` is a Rust program for converting one or more BitTorrent [magnet
links](https://en.wikipedia.org/wiki/Magnet_URI_scheme) into `.torrent` files
by downloading the torrent info from active peers.

At the moment, `demagnetize` only supports basic features of the BitTorrent
protocol.  The following notable features are supported:

- BitTorrent protocol v1
- HTTP (including compact and IPv6 extensions) and UDP trackers
- magnet URIs with info hashes encoded in either hexadecimal or base32
- Fast extension ([BEP 6](https://www.bittorrent.org/beps/bep_0006.html))
- UDP tracker protocol extensions ([BEP
  41](https://www.bittorrent.org/beps/bep_0041.html))

The following features are not currently supported but are planned, in no
particular order:

- Encryption
- Distributed hash tables
- BitTorrent protocol v2
- `x.pe` parameters in magnet links
- uTP

`demagnetize` is a translation of a Python program by the same author; you can
find the Python version at <https://github.com/jwodder/demagnetize>.


Installation
============

Release Assets
--------------

Prebuilt binaries for the most common platforms are available as GitHub release
assets.  [The page for the latest
release](https://github.com/jwodder/demagnetize-rs/releases/latest) lists these
under "Assets", along with installer scripts for both Unix-like systems and
Windows.

As an alternative to the installer scripts, if you have
[`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall) on your
system, you can use it to download & install the appropriate release asset for
your system for the latest version of `demagnetize` by running `cargo binstall
demagnetize`.

Installing from Source
----------------------

If you have [Rust and Cargo
installed](https://www.rust-lang.org/tools/install), you can build the latest
release of `demagnetize` from source and install it in `~/.cargo/bin` by
running:

    cargo install demagnetize

`demagnetize` has the following Cargo features, selectable via the `--features
<LIST>` option to `cargo install`:

- `native-tls` — Use [`native-tls`](https://github.com/sfackler/rust-native-tls)
  for TLS support.  This feature is enabled by default.

- `native-tls-vendored` — Like `native-tls`, but compile a vendored copy of
  OpenSSL into `demagnetize` instead of using the platform's copy at runtime.
  This makes it possible to build `demagnetize` on one system and run it on
  another system that has a different version of OpenSSL.

  This feature has no effect on Windows and macOS, where OpenSSL is not used.

- `rustls` — Use [`rustls`](https://github.com/rustls/rustls) for TLS support.
  When selecting this feature, be sure to also supply the
  `--no-default-features` option in order to disable `native-tls`.

    - The release assets are built using this feature.


Usage
=====

    demagnetize [<global options>] <subcommand> ...

The `demagnetize` command has two main general-purpose subcommands, `get` (for
converting a single magnet link) and `batch` (for converting a file of magnet
links).  There are also two low-level commands, `query-tracker` (for getting a
list of peers from a single tracker) and `query-peer` (for getting torrent
metadata from a single peer).

Global Options
--------------

- `-c <file>`, `--config <file>` — Specify the configuration file to use.  See
  "Configuration" below for the default config file location.

- `-l <level>`, `--log-level <level>` — Set the log level to the given value.
  Possible values are "`OFF`", "`ERROR`", "`WARN`", "`INFO`", "`DEBUG`", and
  "`TRACE`" (all case-insensitive).  [default value: `INFO`]

- `--no-config` — Use the default configuration settings and do not read from
  any configuration files


`demagnetize get`
-----------------

    demagnetize [<global options>] get [<options>] <magnet-link>

Convert a single magnet link specified on the command line to a `.torrent`
file.  (Note that you will likely have to quote the link in order to prevent it
from being interpreted by the shell.)  By default, the file is saved at
`{name}.torrent`, where `{name}` is replaced by the value of the `name` field
from the torrent info, but a different path can be set via the `--outfile`
option.

### Options

- `-o PATH`, `--outfile PATH` — Save the `.torrent` file to the given path.
  The path may contain a `{name}` placeholder, which will be replaced by the
  (sanitized) name of the torrent, and/or a `{hash}` placeholder, which will be
  replaced by the torrent's info hash in hexadecimal.  Specifying `-` will
  cause the torrent to be written to standard output.  [default:
  `{name}.torrent`]


`demagnetize batch`
-------------------

    demagnetize [<global options>] batch [<options>] <file>

Read magnet links from `<file>` (or from standard input if `<file>` is `-`),
one per line (ignoring empty lines and lines that start with `#`), and convert
each one to a `.torrent` file.  By default, each file is saved at
`{name}.torrent`, where `{name}` is replaced by the value of the `name` field
from the torrent info, but a different path can be set via the `--outfile`
option.

### Options

- `-o PATH`, `--outfile PATH` — Save the `.torrent` files to the given path.
  The path may contain a `{name}` placeholder, which will be replaced by the
  (sanitized) name of each torrent, and/or a `{hash}` placeholder, which will
  be replaced by each torrent's info hash in hexadecimal.  [default:
  `{name}.torrent`]


`demagnetize query-tracker`
---------------------------

    demagnetize [<global options>] query-tracker [<options>] <tracker> <info-hash>

Query the given tracker (specified as an HTTP or UDP URL) for peers serving the
torrent with the given info hash (specified as a 40-character hex string or
32-character base32 string), and print out the the retrieved peers' addresses
in the form "IP:PORT".

### Options

- `-J`, `--json` — Print out the peers as JSON objects, one per line


`demagnetize query-peer`
------------------------

    demagnetize [<global options>] query-peer [<options>] <peer> <info-hash>

Query the given peer (specified as an address in "IPv4:PORT" or "[IPv6]:PORT"
format) for the metadata of the torrent with the given info hash (specified as
a 40-character hex string or 32-character base32 string), and save the metadata
to a file.  By default, the file is saved at `{name}.torrent`, where `{name}`
is replaced by the value of the `name` field from the torrent info, but a
different path can be set via the `--outfile` option.

Note that, unlike the `.torrent` files produced by the `get` and `batch`
commands, the files produced by this command will not contain tracker
information.

### Options

- `-o PATH`, `--outfile PATH` — Save the `.torrent` file to the given path.
  The path may contain a `{name}` placeholder, which will be replaced by the
  (sanitized) name of the torrent, and/or a `{hash}` placeholder, which will be
  replaced by the torrent's info hash in hexadecimal.  Specifying `-` will
  cause the torrent to be written to standard output.  [default:
  `{name}.torrent`]


Configuration
=============

`demagnetize` can be configured via a [TOML](https://toml.io) file whose
default location depends on your OS:

- Linux — `~/.config/demagnetize/config.toml` or `$XDG_CONFIG_HOME/demagnetize/config.toml`
- macOS — `~/Library/Application Support/demagnetize/config.toml`
- Windows — `%USERPROFILE%\AppData\Local\demagnetize\config.toml`

This file may contain the following tables & keys, all of which are optional:

- `[general]` — settings that don't fit anywhere more specific
    - `batch-jobs` (positive integer; default 50) — the maximum number of
      magnet links that the `batch` command will operate on at once

- `[peers]` — settings for interacting with peers
    - `handshake-timeout` (nonnegative integer; default 60) — When connecting
      to a peer, if the TCP connection and BitTorrent handshake are not both
      completed within this many seconds, the peer is abandoned.
    - `jobs-per-magnet` (positive integer; default 30) — the maximum number of
      peers per magnet link that `demagnetize` will communicate with at once

- `[trackers]` — settings for interacting with trackers
    - `announce-timeout` (nonnegative integer; default 30) — When sending a
      "started" announcement to a tracker & receiving a list of peers in
      response, if the task does not complete within this many seconds, the
      tracker is abandoned.
    - `jobs-per-magnet` (positive integer; default 30) — the maximum number of
      trackers per magnet link that `demagnetize` will communicate with at once
    - `local-port` — the port number that `demagnetize` will tell trackers it's
      receiving peer connections on
        - This can be either a port number or a string containing two port
          numbers separated by a hyphen (in which case a port in the given
          inclusive range will be chosen at random).  The default is
          `"1025-65535"`, which selects any nonprivileged port at random.
        - Note that `demagnetize` does not actually use the port in question,
          and no attempt is made to ensure the port is not already in use.  On
          the other hand, `demagnetize` sends a "stop" announcement to each
          tracker immediately after receiving the list of peers, so hopefully
          no other peers will see the port number.
    - `numwant` (positive integer; default 50) — the number of peers to request
      from each tracker
    - `shutdown-timeout` (nonnegative integer; default 3) — At the end of
      program operation, wait this many seconds for any outstanding "stopped"
      announcements to complete; any tasks still running after the timeout are
      forcibly cancelled.
