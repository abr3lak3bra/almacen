use inquire::Text;
use anyhow::{bail, Result};
use base64::prelude::*;
use dotenv::dotenv;
use colored::Colorize;
use cryptojs_rust::{
    aes::{
        AesEncryptor, AesDecryptor
    }, CryptoOperation, Mode
};
use comfy_table::{
    Table, 
    Cell, 
    Row as cRow, 
    modifiers::UTF8_ROUND_CORNERS, 
    presets::UTF8_NO_BORDERS, 
    CellAlignment
};
use sqlx::{
    sqlite::SqliteConnectOptions, 
    migrate::MigrateDatabase, 
    SqlitePool, 
    Sqlite, 
    Row
};
use std::{
    fs::{
        self, File
    }, io::Write, path::Path
};

struct Almacen {
    nombre: String,
    key: String
}
struct Conexion {
    pool: SqlitePool
}
struct Password {
    pwd: String
}

const DB: &str = "./db/db.db";
const DB_PATH: &str = "./db";
const FILE_EXPORT: &str = "./files/exportar_datos.csv";
const FILE_IMPORT: &str = "./files/importar_datos.csv";

impl Conexion {
    async fn new() -> Result<Self> {
        if !Sqlite::database_exists(DB).await? {
            if !Path::new(DB_PATH).exists() { fs::create_dir(DB_PATH)?; }
            Sqlite::create_database(DB).await?;
        }

        let op = SqliteConnectOptions::new()
            .filename(DB)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete);

        Ok(Self {
            pool: SqlitePool::connect_with(op).await?
        })
    }
}

impl Password {
    fn new() -> Result<Self> {
        Ok(Self {
            pwd: dotenv::var("PWD")?
        })
    }
}

fn clear_console() {
    print!("\x1B[2J\x1B[1;1H");
}

fn convert(data: &str) -> Result<Vec<u8>> {
    let len = data.len();
    let mut vec = vec![0u8; len];

    if data.is_empty() {
        bail!("Error: Data is empty");
    }

    vec[..len].copy_from_slice(data.as_bytes());
    Ok(vec)
}

async fn create_schema(conexion: &Conexion) -> Result<()> {
    let data = "
        CREATE TABLE IF NOT EXISTS Almacen (
            id INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            key TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
        CREATE INDEX IF NOT EXISTS id_key ON Almacen(key);
    ";

    sqlx::query(data).execute(&conexion.pool).await?;
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

    // [16 bytes salt][16 bytes IV][ciphertext]
    let salt = &data[..16];
    let iv = &data[16..32];
    let ciphertext = &data[32..];

    let mut decryptor = AesDecryptor::new_256_from_password(
        pwd.pwd.as_bytes(), 
        Mode::CBC, 
        salt, 
        Some(iv) 
    )?;

    decryptor.update(ciphertext)?;
    Ok(decryptor.finalize()?)
}

async fn add(conexion: &Conexion, data: &Almacen) -> Result<()> {
    let transaction = conexion.pool.begin().await?;

    let qry = "INSERT INTO Almacen (nombre, key) VALUES (?1, ?2);";

    sqlx::query(qry)
        .bind(&data.nombre)
        .bind(&data.key)
        .execute(&conexion.pool)
        .await?;

    transaction.commit().await?;
    Ok(())
}

async fn view_all(conexion: &Conexion) -> Result<()> {
    let rows = sqlx::query("SELECT nombre, key FROM Almacen")
        .fetch_all(&conexion.pool)
        .await?;

    let total = rows.len();
    let mut tabla = Table::new();

    tabla.load_preset(UTF8_NO_BORDERS).apply_modifier(UTF8_ROUND_CORNERS);
    tabla.set_header(vec![
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);
    
    for row in rows {
        let decoded = BASE64_STANDARD.decode(row.get::<String, _>(1))?;
        let decrypted = decrypt(decoded)?;

        tabla.add_row(cRow::from(vec![
            Cell::new(row.get::<String, _>(0)),
            Cell::new(String::from_utf8(decrypted)?),
        ]));
    }
    println!("{}\n", tabla);
    println!("Total Registros: {}", &total);

    Ok(())
}

async fn export_all(conexion: &Conexion) -> Result<()> {
    let rows = sqlx::query("SELECT nombre, key FROM Almacen")
        .fetch_all(&conexion.pool)
        .await?;

    let mut file = File::create(FILE_EXPORT)?;

    for row in rows {
        let decoded = BASE64_STANDARD.decode(row.get::<String, _>(1))?;
        let decrypt = decrypt(decoded)?;
        let mut result = String::from_utf8(decrypt)?;
        result.retain(|c| c != '\0');
        writeln!(file, "{},{}", row.get::<String, _>(0), result)?;
    }

    Ok(())
}

async fn import_all(conexion: &Conexion) -> Result<()> {
    let contents = fs::read_to_string(FILE_IMPORT)?;

    for line in contents.lines() {
        let parts = &line.split(",").map(|s| s.trim()).collect::<Vec<&str>>();

        if parts.len() != 2 {
            bail!("Error: Incorrect number of arguments");
        }

        let converted = convert(parts[1])?;
        let encrypted = encrypt(&converted)?;

        add(conexion, &Almacen {
            nombre: parts[0].to_string(),
            key: BASE64_STANDARD.encode(&encrypted),
        }).await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    clear_console();
    dotenv().ok();

    let conexion = Conexion::new().await?;

    loop {
        println!("{}, {}, {}, {}, {}, {} - abr{}lak{}bra", 
            "s".red(), 
            "a".green(), 
            "v".cyan(),
            "i".purple(), 
            "e".blue(), 
            "q".blue(), 
            "3".green(), 
            "3".green());

        println!(" ");

        let entrada = Text::new("").prompt()?;

        let partes: Vec<&str> = entrada.split_whitespace().collect();

        match partes.as_slice() {
            ["s"] => {
                create_schema(&conexion).await?;
                clear_console();
            },
            ["a", nombre, key] => {
                let converted = convert(key)?;
                let encrypted = encrypt(&converted)?;

                add(&conexion, &Almacen {
                    nombre: nombre.to_string(),
                    key: BASE64_STANDARD.encode(&encrypted)
                }).await?;
                clear_console();
            },
            ["v"] => {
                clear_console();
                println!(" ");
                view_all(&conexion).await?;
                println!(" ");
            },
            ["e"] => {
                export_all(&conexion).await?;
                clear_console();
            },
            ["i"] => {
                import_all(&conexion).await?;
                clear_console();
            },
            ["q"] => {
                println!("Saliendo...");
                break;
            },
            _ => {
                clear_console();
            }
        }
    }
    Ok(())
}