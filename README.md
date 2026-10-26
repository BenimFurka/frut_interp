# Frut Interpreter

[![Crates.io](https://img.shields.io/crates/v/frut_interp.svg)](https://crates.io/crates/frut_interp)
[![Documentation](https://docs.rs/frut_interp/badge.svg)](https://docs.rs/frut_interp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A command-line interpreter for the Frut programming language, built on top of the `frut_lib` crate.

## Installation
```bash
cargo install frut_interp
```

## Usage
```bash
frut [OPTIONS] [ENTRY]
```

`ENTRY` is the path to the entry `.ft` file. If omitted, `<project>/main.ft` is used.

### Options

| Option | Description |
| --- | --- |
| `-p, --project <DIR>` | Project root. Defaults to the entry file's directory. |
| `-n, --name <NAME>` | Import name of the project library. Default: `self`. |
| `-e, --entry <FILE>` | Entry file, relative to `--project` when given. |
| `-l, --lib <NAME>=<PATH>` | Mount the directory `PATH` as library `NAME` (repeatable). `-l std=<PATH>` overrides the embedded std. |
| `-f, --format <FORMAT>` | Output format: `text` (default) or `json`. |
| `--no-std` | Do not mount the standard library. |
| `--version` | Print the backend version. |
| `-h, --help` | Print usage. |

Relative entry paths are resolved against `--project`, which is how the
package manager invokes the backend (`--entry main.ft --project /abs/dir`).

### Exit codes

- `0` — success
- `1` — parse, load, semantic, or runtime error
- `2` — invalid arguments / unreadable entry

### JSON output

With `-f json`, errors and the final status are emitted as a single JSON
object, intended for tooling (package manager, LSP, CI):

```json
{"success":false,"errors":[{"code":...,"type":"...","message":"...","file":"...","line":1,"column":1,"snippet":"..."}]}
```

On success: `{"success":true,"errors":[]}`.

## Standard library

The standard library is **embedded in the binary** — it is mounted as `std`
by default, so `import std.io.*;` works out of the box with no configuration.

The embedded modules are `std.io`, `std.math`, `std.option`, `std.strings`,
`std.vec`, `std.bytes`, `std.fs`, `std.time`, and `std.process` (each with a
corresponding `std.native.*` implementation module).

An explicit `-l std=<path>` or the `FRUT_STD_PATH` environment variable
(pointing at a directory) overrides the embedded copy; `--no-std` disables it.
There is no implicit on-disk lookup — an unrelated `std/` directory does not
shadow the embedded library.

## Library usage

The crate also exposes the interpreter as a library:

```rust
use frut_interp::interpreter::Interpreter;
use frut_interp::loader::{build_tree, LibMount, ProjectMount};
```

- `loader::build_tree` scans directories into a module tree
  (`root -> { <project>, std?, <lib>... }`) used for import resolution.
- `loader::EMBEDDED_STD` / `libs::embedded_std` provide the embedded std.
- `interpreter::Interpreter` executes the parsed AST.

## Example
A simple Frut program that calculates factorials:

```frut
import std.io.*;

// Calculate factorial of a number
func factorial(n: int): int {
    if n <= 1 {
        return 1;
    } else {
        return n * factorial(n - 1);
    }
}

// Calculate and print factorial of 5
var result: int = factorial(5);
println("Factorial of 5 is: " + result as string);
```

Save this as `factorial.ft` and run:

```bash
frut factorial.ft
```

A more complete tour of the language lives in [`examples/frut.ft`](examples/frut.ft).

## Documentation
For documentation, including language syntax, visit:
- [Language Reference](https://github.com/BenimFurka/frut_lib/wiki)

## License
Licensed under the Apache License, Version 2.0 [LICENSE](LICENSE).
