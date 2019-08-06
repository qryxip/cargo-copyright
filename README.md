# cargo-copyright

[![Build Status](https://img.shields.io/travis/com/qryxip/cargo-copyright/master.svg?label=windows%20%26%20macos%20%26%20linux)](https://travis-ci.com/qryxip/cargo-copyright)
![Maintenance](https://img.shields.io/maintenance/yes/2019)
![license](https://img.shields.io/badge/license-MIT%20OR%20Apache%202.0-blue)

Generates appropriate license and copyright notices.

## Installation

`cargo-copyright` is not yet uploaded to [crates.io](https://crates.io).

```console
$ cargo install --git https://github.com/qryxip/cargo-license
```

## Usage

```
cargo-copyright 0.0.0
Ryo Yamashita <qryxip@gmail.com>
Generates appropriate license and copyright notices.

USAGE:
    cargo copyright [FLAGS] [OPTIONS]

FLAGS:
        --exclude-unused    Exclude unused crates
        --prefer-links      Always emits URLs even if `LICENSE` files found
    -h, --help              Prints help information
    -V, --version           Prints version information

OPTIONS:
        --cargo-command <COMMAND>    Cargo command for `exclude-unused` [default: clippy]  [possible values: clippy, check]
        --format <FORMAT>            Format [default: markdown]  [possible values: markdown]
        --bin <STRING>               Target `bin`
        --manifest-path <STRING>     Path to Cargo.toml
        --color <WHEN>               Coloring [default: auto]  [possible values: auto, always, never]
```

## Supported licenses

- [`MIT`](https://spdx.org/licenses/MIT.html)
- [`Apache-2.0`](https://spdx.org/licenses/Apache-2.0.html)
- [`BSD-3-Clause`](https://spdx.org/licenses/BSD-3-Clause.html)
- [`MPL-2.0`](https://spdx.org/licenses/MPL-2.0.html)
- [`ISC`](https://spdx.org/licenses/ISC.html)
- [`CC0-1.0`](https://spdx.org/licenses/CC0-1.0.html)
- [`Unlicense`](https://spdx.org/licenses/Unlicense.html)
- [`WTFPL`](https://spdx.org/licenses/WTFPL.html)

## Example

```
$ cargo copyright --prefer-links
[INFO] `/home/ryo/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo metadata --format-version 1` in /home/ryo/src/cargo-copyright
[INFO] exit code: 0
[INFO] atty v0.2.13: "MIT" → (Mit, Some("LICENSE"))
[INFO] cargo_metadata v0.8.1: "MIT" → (Mit, Some("LICENSE-MIT"))
[INFO] derive_more v0.15.0: "MIT" → (Mit, Some("LICENSE"))
[INFO] env_logger v0.6.2: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] failure v0.1.5: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] filetime v0.2.6: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] fixedbitset v0.1.9: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] if_chain v1.0.0: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] indexmap v1.0.2: "Apache-2.0/MIT" → (Mit, Some("LICENSE-MIT"))
[INFO] itertools v0.8.0: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] log v0.4.8: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] maplit v1.0.1: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] once_cell v0.2.4: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] opaque_typedef v0.0.5: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT.txt"))
[INFO] opaque_typedef_macros v0.0.5: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT.txt"))
[INFO] regex v1.2.1: "MIT/Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] serde v1.0.98: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] serde_json v1.0.40: "MIT OR Apache-2.0" → (Mit, Some("LICENSE-MIT"))
[INFO] structopt v0.2.18: "Apache-2.0/MIT" → (Mit, Some("LICENSE-MIT"))
[INFO] strum v0.15.0: "MIT" → (Mit, None)
[INFO] strum_macros v0.15.0: "MIT" → (Mit, None)
[INFO] termcolor v1.0.5: "Unlicense OR MIT" → (Mit, Some("LICENSE-MIT"))
# License and copyright notices

## [Rust](https://www.rust-lang.org)
[MIT License]

## [atty v0.2.13](https://crates.io/crates/atty/0.2.13)
[MIT License]
Copyright (c) 2015-2019 Doug Tangren

## [cargo_metadata v0.8.1](https://crates.io/crates/cargo_metadata/0.8.1)
[MIT License]

## [derive_more v0.15.0](https://crates.io/crates/derive_more/0.15.0)
[MIT License]

## [env_logger v0.6.2](https://crates.io/crates/env_logger/0.6.2)
[MIT License]
Copyright (c) 2014 The Rust Project Developers

## [failure v0.1.5](https://crates.io/crates/failure/0.1.5)
[MIT License]

## [filetime v0.2.6](https://crates.io/crates/filetime/0.2.6)
[MIT License]
Copyright (c) 2014 Alex Crichton

## [fixedbitset v0.1.9](https://crates.io/crates/fixedbitset/0.1.9)
[MIT License]
Copyright (c) 2015-2017

## [if_chain v1.0.0](https://crates.io/crates/if_chain/1.0.0)
[MIT License]
Copyright (c) 2018 Chris Wong

## [indexmap v1.0.2](https://crates.io/crates/indexmap/1.0.2)
[MIT License]
Copyright (c) 2016--2017

## [itertools v0.8.0](https://crates.io/crates/itertools/0.8.0)
[MIT License]
Copyright (c) 2015

## [log v0.4.8](https://crates.io/crates/log/0.4.8)
[MIT License]
Copyright (c) 2014 The Rust Project Developers

## [maplit v1.0.1](https://crates.io/crates/maplit/1.0.1)
[MIT License]
Copyright (c) 2015

## [once_cell v0.2.4](https://crates.io/crates/once_cell/0.2.4)
[MIT License]

## [opaque_typedef v0.0.5](https://crates.io/crates/opaque_typedef/0.0.5)
[MIT License]
Copyright 2017 YOSHIOKA Takuma

## [opaque_typedef_macros v0.0.5](https://crates.io/crates/opaque_typedef_macros/0.0.5)
[MIT License]
Copyright 2017 YOSHIOKA Takuma

## [regex v1.2.1](https://crates.io/crates/regex/1.2.1)
[MIT License]
Copyright (c) 2014 The Rust Project Developers

## [serde v1.0.98](https://crates.io/crates/serde/1.0.98)
[MIT License]

## [serde_json v1.0.40](https://crates.io/crates/serde_json/1.0.40)
[MIT License]

## [structopt v0.2.18](https://crates.io/crates/structopt/0.2.18)
[MIT License]

## [strum v0.15.0](https://crates.io/crates/strum/0.15.0)
[MIT License]

## [strum_macros v0.15.0](https://crates.io/crates/strum_macros/0.15.0)
[MIT License]

## [termcolor v1.0.5](https://crates.io/crates/termcolor/1.0.5)
[MIT License]

[MIT License]: https://opensource.org/licenses/MIT
```

## License

Licensed under [MIT](https://opensource.org/licenses/MIT) OR [Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0).