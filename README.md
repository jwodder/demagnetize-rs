[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)
[![CI Status](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml/badge.svg)](https://github.com/jwodder/demagnetize-rs/actions/workflows/test.yml)
[![codecov.io](https://codecov.io/gh/jwodder/demagnetize-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/jwodder/demagnetize-rs)
[![Minimum Supported Rust Version](https://img.shields.io/badge/MSRV-1.65-orange)](https://www.rust-lang.org)
[![MIT License](https://img.shields.io/github/license/jwodder/demagnetize-rs.svg)](https://opensource.org/licenses/MIT)

[GitHub](https://github.com/jwodder/demagnetize-rs) | [Issues](https://github.com/jwodder/demagnetize-rs/issues)

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


Usage
=====

    demagnetize [<global options>] <subcommand> ...

The `demagnetize` command has two subcommands, `get` (for converting a single
magnet link) and `batch` (for converting a file of magnet links), both detailed
below.

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
