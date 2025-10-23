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
frut path/to/script.ft
```

## Example
A simple Frut program that calculates factorials:

```frut
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

## Documentation
For documentation, including language syntax, visit:
- [Language Reference](https://github.com/BenimFurka/frut_interp/wiki)

## License
Licensed under the Apache License, Version 2.0 [LICENSE](LICENSE).
