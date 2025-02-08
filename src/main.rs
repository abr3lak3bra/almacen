use crate::schema::almacen::dsl as almacen_dsl;
use crate::models::Registro;
use inquire::Text;
use models::Almacen;
use anyhow::{bail, Result};
use base64::prelude::*;
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, 
    presets::UTF8_NO_BORDERS, 
    Cell, 
    CellAlignment, 
    Row as cRow,
    Table,
};
use cryptojs_rust::{
    aes::{AesDecryptor, AesEncryptor},
    CryptoOperation, Mode,
};
use diesel::{
    prelude::*,
    sqlite::SqliteConnection,
};
use std::{
    env,
    fs::{self, File},
    path::Path,
};

pub mod models;
pub mod schema;

struct Conexion {
    pool: SqliteConnection,
}

struct Password {
    pwd: String,
}

const DB: &str = "./db/db.db";
const DB_PATH: &str = "./db";
const FILE_EXPORT: &str = "./files/exportar_datos.csv";
const FILE_IMPORT: &str = "./files/importar_datos.csv";

impl Conexion {
    fn new() -> Result<Self> {
        if !Path::new(DB_PATH).exists() {
            fs::create_dir(DB_PATH)?;
        }

        Ok(Self {
            pool: SqliteConnection::establish(DB)?,
        })
    }
}

impl Password {
    fn new() -> Result<Self> {
        Ok(Self {
            pwd: env::var("PWD")?,
        })
    }
}

fn clear_console() {
    print!("\x1B[2J\x1B[1;1H");
}

fn create_schema(conexion: &mut Conexion) -> Result<()> {
    let data = "
        CREATE TABLE IF NOT EXISTS Almacen (
            id INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            key TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
        CREATE INDEX IF NOT EXISTS id_key ON Almacen(key);
    ";

    diesel::sql_query(data).execute(&mut conexion.pool)?;
    Ok(())
}

fn remove(conexion: &mut Conexion, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen
        .filter(almacen_dsl::nombre.eq(name)))
        .execute(&mut conexion.pool)?;

    if rows == 0 {
        bail!("No record found with name: {}", name);
    }

    Ok(())
}

fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    let pwd = Password::new()?;

    let mut encryptor = AesEncryptor::new_256_from_password(pwd.pwd.as_bytes(), Mode::CBC)?;
    encryptor.update(data)?;

    Ok(encryptor.finalize()?)
}

fn decrypt(data: Vec<u8>) -> Result<Vec<u8>> {
    let pwd = Password::new()?;

    let salt = &data[..16];
    let iv = &data[16..32];
    let ciphertext = &data[32..];

    let mut decryptor =
        AesDecryptor::new_256_from_password(pwd.pwd.as_bytes(), Mode::CBC, salt, Some(iv))?;

    decryptor.update(ciphertext)?;
    Ok(decryptor.finalize()?)
}

fn add(conexion: &mut Conexion, data: &Almacen) -> Result<()> {
    if almacen_dsl::almacen
        .filter(almacen_dsl::nombre.eq(&data.nombre))
        .count()
        .get_result::<i64>(&mut conexion.pool)?
        > 0
    {
        bail!("Name: {} already exist", &data.nombre);
    }

    diesel::insert_into(almacen_dsl::almacen)
        .values(Registro {
            nombre: &data.nombre,
            key: &data.key,
        })
        .execute(&mut conexion.pool)?;

    Ok(())
}

fn view_all(conexion: &mut Conexion, inicio: &u16, fin: &u16) -> Result<()> {
    let results = almacen_dsl::almacen
        .limit((fin - inicio) as i64)
        .offset(*inicio as i64)
        .load::<Almacen>(&mut conexion.pool)?;

    if results.is_empty() {
        bail!("No hay registros en el rango especificado");
    }

    let total = results.len();
    let mut tabla = Table::new();

    tabla
        .load_preset(UTF8_NO_BORDERS)
        .apply_modifier(UTF8_ROUND_CORNERS);

    tabla.set_header(vec![
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);

    for row in results {
        let decoded = BASE64_STANDARD.decode(&row.key)?;
        let decrypted = decrypt(decoded)?;

        tabla.add_row(cRow::from(vec![
            Cell::new(row.nombre),
            Cell::new(String::from_utf8(decrypted)?),
        ]));
    }
    println!("{}\n", &tabla);
    println!(
        "Mostrando registros del {} al {} - Total: {}",
        &inicio, &fin, &total
    );

    Ok(())
}

fn export_all(conexion: &mut Conexion) -> Result<()> {
    let results = almacen_dsl::almacen.load::<Almacen>(&mut conexion.pool)?;

    let mut writer = csv::Writer::from_writer(File::create(FILE_EXPORT)?);

    for row in results {
        let decoded = BASE64_STANDARD.decode(&row.key)?;
        let decrypted = decrypt(decoded)?;
        let result = String::from_utf8(decrypted)?;
        writer.write_record(&[row.nombre, result])?;
    }

    Ok(())
}

fn import_all(conexion: &mut Conexion) -> Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(FILE_IMPORT)?;

    for line in reader.records() {
        let record = line?;

        if record[0].is_empty() {
            bail!("empty name {}", &record[0]);
        } else if record[1].is_empty() {
            bail!("empty key for name: {}", &record[0]);
        }

        let encrypted = encrypt(record[1].as_bytes())?;

        let _almacen = Almacen {
            id: 0, // Diesel
            nombre: record[0].to_string(),
            key: BASE64_STANDARD.encode(&encrypted),
        };

        add(conexion, &_almacen)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    clear_console();
    dotenvy::dotenv()?;

    let mut conexion = Conexion::new()?;

    loop {
        println!(
            "{}, {}, {}, {}, {}, {}, {} - abr{}lak{}bra",

            "s".red(),
            "a".green(),
            "v".cyan(),
            "i".purple(),
            "e".blue(),
            "r".cyan(),
            "q".blue(),
            "3".green(),
            "3".green()
        );

        println!(" ");

        let entrada = Text::new("").prompt()?;
        let partes: Vec<&str> = entrada.split_whitespace().collect();

        match partes.as_slice() {
            ["s"] => {
                create_schema(&mut conexion)?;
                clear_console();
            }
            ["a", _nombre, _key] => {
                let encrypted = encrypt(_key.as_bytes())?;

                add(
                    &mut conexion,
                    &Almacen {
                        id: 0, // Diesel
                        nombre: _nombre.to_string(),
                        key: BASE64_STANDARD.encode(&encrypted),
                    },
                )?;
                clear_console();
            }
            ["v", inicio, fin] => {
                clear_console();
                println!(" ");
                let pg_inicio = inicio.parse::<u16>()?;
                let pg_fin = fin.parse::<u16>()?;
                view_all(&mut conexion, &pg_inicio, &pg_fin)?;
                println!(" ");
            }
            ["e"] => {
                export_all(&mut conexion)?;
                clear_console();
            }
            ["i"] => {
                import_all(&mut conexion)?;
                clear_console();
            }
            ["r", _nombre] => {
                remove(&mut conexion, _nombre)?;
                clear_console();
            }
            ["q"] => {
                println!("Saliendo...");
                break;
            }
            _ => {
                clear_console();
            }
        }
    }
    Ok(())
}
