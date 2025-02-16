# Almacen - Interactive key store

Argon2id for password hash.

Ring with ChaCha20 for key.

Keys are stored in db/db.db.

Ring with ChaCha20 for the file db.db.

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
a -> Add -> Usage: a testi1 0xac....
v -> View -> Usage: v 0 10 -> Display records from id 0 to 10
i -> Import
e -> Export
r -> Remove -> Usage: r testi1
q -> Quit
```
## Author

- [abr3lak3bra](https://github.com/abr3lak3bra)