use crate::models::{Registro, RegistroRecovery};
use crate::schema::almacen::dsl as almacen_dsl;
use crate::schema::recovery::dsl as recovery_dsl;
use anyhow::{bail, Ok, Result};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::Argon2;
use base64::prelude::*;
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_NO_BORDERS, Cell, CellAlignment, Row as cRow,
    Table,
};
use cryptojs_rust::{
    aes::{AesDecryptor, AesEncryptor},
    CryptoOperation, Mode,
};
use diesel::{dsl::exists, prelude::*, sqlite::SqliteConnection};
use inquire::Text;
use models::Almacen;
use std::{
    env,
    fs::{self, File},
    path::Path,
};

mod models;
mod schema;

struct Conexion {
    pool: SqliteConnection,
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

fn create_1_instance(conexion: &mut Conexion) -> Result<()> {
    let master = env::var("PWD")?;
    let mut new_hash = [0u8; 32];
    let salt_ = SaltString::generate(&mut OsRng);

    Argon2::default()
        .hash_password_into(
            &master.clone().into_bytes(),
            salt_.to_string().as_bytes(),
            &mut new_hash,
        )
        .unwrap();

    diesel::insert_into(recovery_dsl::recovery)
        .values(RegistroRecovery {
            salt: salt_.as_ref(),
            hash: &BASE64_URL_SAFE.encode(new_hash),
        })
        .execute(&mut conexion.pool)?;

    Ok(())
}

fn create_2_instance(conexion: &mut Conexion) -> Result<String> {
    let master = env::var("PWD")?;
    let mut new_hash = [0u8; 32];
    let salt_ = get_salt_from_db(conexion)?;

    Argon2::default()
        .hash_password_into(
            &master.clone().into_bytes(),
            salt_.to_string().as_bytes(),
            &mut new_hash,
        )
        .expect("first hashing");

    Ok(BASE64_STANDARD.encode(new_hash))
}

fn get_salt_from_db(conexion: &mut Conexion) -> Result<String> {
    let result = recovery_dsl::recovery
        .select(recovery_dsl::salt)
        .limit(1)
        .load::<String>(&mut conexion.pool)?;

    if let Some(salt) = result.into_iter().next() {
        Ok(salt)
    } else {
        bail!("No salt found in database")
    }
}

fn get_salt_hash_from_db(conexion: &mut Conexion) -> Result<Option<(String, String)>> {
    let result = recovery_dsl::recovery
        .select((recovery_dsl::salt, recovery_dsl::hash))
        .limit(1)
        .load::<(String, String)>(&mut conexion.pool)?;

    Ok(result.into_iter().next())
}

fn verify_hash(hash_new: &str, hash_db: &str) -> Result<()> {
    let hash_db_bytes = BASE64_URL_SAFE.decode(hash_db)?;
    let hash_new_bytes = BASE64_URL_SAFE.decode(hash_new)?;

    if hash_new_bytes != hash_db_bytes {
        bail!("Password verification failed");
    }

    Ok(())
}

fn clear_console() {
    print!("\x1B[2J\x1B[1;1H");
}

fn check_name(nombre: &str) -> Result<()> {
    if nombre.len() > 9 {
        bail!(
            "El nombre {}... excede el limite de caracteres permitidos",
            &nombre[0..9]
        );
    }

    if !nombre.chars().all(|c| c.is_alphanumeric() || c == '_') {
        bail!("El nombre solo puede contener letras, numeros y guiones bajos");
    }

    Ok(())
}

fn create_schema(conexion: &mut Conexion, what: bool) -> Result<()> {
    if what {
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS Recovery (
                status BOOL DEFAULT FALSE,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
        ",
        )
        .execute(&mut conexion.pool)?;
    } else {
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS Almacen (
                id INTEGER PRIMARY KEY,
                nombre TEXT NOT NULL,
                key TEXT NOT NULL
            );

        CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
        CREATE INDEX IF NOT EXISTS id_key ON Almacen(key);
        ",
        )
        .execute(&mut conexion.pool)?;
    }
    Ok(())
}

fn remove(conexion: &mut Conexion, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(name)))
        .execute(&mut conexion.pool)?;

    if rows == 0 {
        bail!("No record found with name: {}", name);
    }

    Ok(())
}

fn encrypt(data: &[u8], master: &String) -> Result<Vec<u8>> {
    let mut encryptor = AesEncryptor::new_256_from_password(master.as_bytes(), Mode::CBC)?;
    encryptor.update(data)?;

    Ok(encryptor.finalize()?)
}

fn decrypt(data: Vec<u8>, master: &String) -> Result<Vec<u8>> {
    let _salt = &data[..16];
    let iv = &data[16..32];
    let ciphertext = &data[32..];

    let mut decryptor =
        AesDecryptor::new_256_from_password(master.as_bytes(), Mode::CBC, _salt, Some(iv))?;

    decryptor.update(ciphertext)?;
    Ok(decryptor.finalize()?)
}

fn add(conexion: &mut Conexion, data: &Almacen) -> Result<()> {
    if diesel::select(exists(
        almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&data.nombre)),
    ))
    .get_result::<bool>(&mut conexion.pool)?
    {
        bail!("Name {} already exist", &data.nombre);
    }

    diesel::insert_into(almacen_dsl::almacen)
        .values(Registro {
            nombre: &data.nombre,
            key: &data.key,
        })
        .execute(&mut conexion.pool)?;

    Ok(())
}

fn view_all(conexion: &mut Conexion, master: &String, inicio: &u16, fin: &u16) -> Result<()> {
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
        let decoded = BASE64_URL_SAFE.decode(&row.key)?;
        let decrypted = decrypt(decoded, master)?;

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

fn export_all(conexion: &mut Conexion, master: &String) -> Result<()> {
    let results = almacen_dsl::almacen.load::<Almacen>(&mut conexion.pool)?;

    let mut writer = csv::Writer::from_writer(File::create(FILE_EXPORT)?);

    for row in results {
        let decoded = BASE64_URL_SAFE.decode(&row.key)?;
        let decrypted = decrypt(decoded, master)?;
        let result = String::from_utf8(decrypted)?;
        writer.write_record(&[row.nombre, result])?;
    }

    Ok(())
}

fn import_all(conexion: &mut Conexion, master: &String) -> Result<()> {
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

        let encrypted = encrypt(record[1].as_bytes(), master)?;

        let _almacen = Almacen {
            id: 0,
            nombre: record[0].to_string(),
            key: BASE64_URL_SAFE.encode(&encrypted),
        };

        add(conexion, &_almacen)?;
    }

    Ok(())
}

fn status(conexion: &mut Conexion) -> Result<bool> {
    if diesel::select(exists(
        recovery_dsl::recovery.filter(recovery_dsl::status.eq(true)),
    ))
    .get_result::<bool>(&mut conexion.pool)?
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn update_status(conexion: &mut Conexion) -> Result<()> {
    if diesel::update(recovery_dsl::recovery)
        .set(recovery_dsl::status.eq(true))
        .execute(&mut conexion.pool).is_ok()
    {
        Ok(())
    } else {
        bail!("Updating status");
    }
}

fn main() -> Result<()> {
    clear_console();
    dotenvy::dotenv()?;

    let master_string = env::var("PWD")?;
    let mut conexion = Conexion::new()?;

    create_schema(&mut conexion, true)?;
    let status_ = status(&mut conexion)?;

    if !status_ {
        create_1_instance(&mut conexion)?;
    } else {
        let hash_new = create_2_instance(&mut conexion)?;
        let salt_hash_db = get_salt_hash_from_db(&mut conexion)?;

        if let Some((_, hash_db)) = salt_hash_db {
            verify_hash(&hash_new, &hash_db)?;
        } else {
            bail!("No password hash found in db");
        }
    }

    update_status(&mut conexion)?;

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

        let entrada = Text::new("\x1b[32m->\x1b[0m").prompt()?;
        let partes: Vec<&str> = entrada.split_whitespace().collect();

        match partes.as_slice() {
            ["s"] => {
                create_schema(&mut conexion, false)?;
                clear_console();
            }
            ["a", name, privkey] => {
                check_name(name)?;
                let encrypted = encrypt(privkey.as_bytes(), &master_string)?;

                add(
                    &mut conexion,
                    &Almacen {
                        id: 0, // Diesel
                        nombre: name.to_string(),
                        key: BASE64_URL_SAFE.encode(&encrypted),
                    },
                )?;
                clear_console();
            }
            ["v", inicio, fin] => {
                clear_console();
                println!(" ");
                let pg_inicio = inicio.parse::<u16>()?;
                let pg_fin = fin.parse::<u16>()?;
                view_all(&mut conexion, &master_string, &pg_inicio, &pg_fin)?;
                println!(" ");
            }
            ["e"] => {
                export_all(&mut conexion, &master_string)?;
                clear_console();
            }
            ["i"] => {
                import_all(&mut conexion, &master_string)?;
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
