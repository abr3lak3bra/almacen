# Almacen

Almacen is a Rust-based application designed to securely store and manage sensitive data using encryption. It utilizes SQLite for data storage and the Ring library for cryptographic operations.

- **Private Directory**: Contains sensitive files, including the `private_key.bin`, which stores the encryption key used for encrypt/decrypt data.

## Features

- Secure storage of sensitive data using ChaCha20-Poly1305 encryption.
- Command-line interface for adding, viewing, importing, and exporting data.
- Memory locking to prevent sensitive data from being swapped to disk.

## Prerequisites

- Rust and Cargo.

## Setup

Clone the repository

```bash
  git clone https://github.com/abr3lak3bra/almacen.git
```

Go to the project directory

```bash
  cd almacen
```

## Run

```bash
  cargo run
```

## Menu Usage
```bash
a -> Add -> Usage: a testi1 0xac....
v -> View -> Usage: v 0 10 -> Display records from id 0 to 10
i -> Import
e -> Export
r -> Remove -> Usage: r testi1
q -> Quit
```
## Author

- [abr3lak3bra](https://github.com/abr3lak3bra)