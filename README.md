# nookcodes

Small Rust library for generating and decoding Animal Crossing: GameCube passwords.

Supports generating and decoding all types of AC passwords.

## Installation

Add nookcodes as a dependency to your Cargo.toml:

```toml
[dependencies]
nookcodes = "0.5.0"
```

## Example
```rust
use nookcodes::{
    PasswordBytes,
    decode,
    PASSWORD_LEN
};

const CHAR_MAP: [&str; 256] = [ // table mapping AC text encoding to Unicode
    ...
];

fn ac2ascii(input: &[u8]) -> String {
    let mut output = String::new();

    for b in input {
        output.push_str(CHAR_MAP[*b as usize]);
    }

    output
}

fn main() {
    let bytes = PasswordBytes::from([ // example user password
        0x6A, 0x78, 0x57, 0x40, 0x6C, 0x40, 0x50,
        0x44, 0x56, 0x26, 0x4F, 0x4F, 0x79, 0x48,
        0x56, 0x50, 0x47, 0x73, 0x5A, 0x67, 0x74,
        0x43, 0x50, 0x33, 0xD1, 0x65, 0x48, 0x45,
    ]);

    let password = decode(&bytes).expect("Failed to decode");

    println!("{}", ac2ascii(password.str0())); // prints "ABCDEFGH" (the recipient's player name)
}
```

# License
MIT