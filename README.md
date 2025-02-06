# Almacen

A simple key store

Key is encrypted with AES 256, Salt and IV use thread_rng() from AesEncryptor.

Keys are stored in db/db.db encrypted and base64-encoded.

## Environment Variables

To run this project, you will need to change the `PWD` environment var to your .env file.

WARNING! delete `PWD` var or delete .env file after use

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

## Menu
```bash
s -> Setup
a -> Add
v -> View
i -> Import
e -> Export
q -> Quit
```
## Authors

- [abr3lak3bra](https://github.com/abr3lak3bra)