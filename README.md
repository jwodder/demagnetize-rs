[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![CI Status](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml/badge.svg)](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml)
[![codecov.io](https://codecov.io/gh/jwodder/demagnetize-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/jwodder/demagnetize-rs)
[![Minimum Supported Rust Version](https://img.shields.io/badge/MSRV-1.74-orange)](https://www.rust-lang.org)
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

In order to install `demagnetize`, you first need to have [Rust and Cargo
installed](https://www.rust-lang.org/tools/install).  You can then build the
latest release of `demagnetize` and install it in `~/.cargo/bin` by running:

    cargo install demagnetize


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

- `-l <level>`, `--log-level <level>` — Set the log level to the given value.
  Possible values are "`OFF`", "`ERROR`", "`WARN`", "`INFO`", "`DEBUG`", and
  "`TRACE`" (all case-insensitive).  [default value: `INFO`]


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

Read magnet links from `<file>`, one per line (ignoring empty lines and lines
that start with `#`), and convert each one to a `.torrent` file.  By default,
each file is saved at `{name}.torrent`, where `{name}` is replaced by the value
of the `name` field from the torrent info, but a different path can be set via
the `--outfile` option.

### Options

- `-o PATH`, `--outfile PATH` — Save the `.torrent` files to the given path.
  The path may contain a `{name}` placeholder, which will be replaced by the
  (sanitized) name of each torrent, and/or a `{hash}` placeholder, which will
  be replaced by each torrent's info hash in hexadecimal.  [default:
  `{name}.torrent`]


`demagnetize query-tracker`
---------------------------

    demagnetize [<global options>] query-tracker <tracker> <info-hash>

Query the given tracker (specified as an HTTP or UDP URL) for peers serving the
torrent with the given info hash (specified as a 40-character hex string or
32-character base32 string), and print out the the retrieved peers' addresses
in the form "IP:PORT".


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
