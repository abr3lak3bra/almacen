# Almacen - Simple key store

Key is encrypted with AES 256, Salt and IV use thread_rng() from fn AesEncryptor (cryptojs_rust).

Keys are stored in db/db.db encrypted and base64-encoded.

## Environment Variables

To run this project, you will need to change the `PWD` environment var to your .env file.

WARNING! delete `PWD` environment var or delete .env file after use.

## Run

Clone the project

```bash
  git clone https://github.com/abr3lak3bra/almacen
```

Go to the project directory

```bash
  cd almacen
```

Run

```bash
  cargo run
```

## Menu Usage
```bash
s -> Setup
a -> Add -> Usage: a testi1 0xac....
v -> View -> Usage: v 0 10 -> this will display records from id 0 to 10
i -> Import
e -> Export
r -> Remove -> Usage: r testi1
q -> Quit
```
## Author

- [abr3lak3bra](https://github.com/abr3lak3bra)