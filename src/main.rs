use crate::schema::almacen::dsl as almacen_dsl;
use anyhow::{Ok, Result};
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_NO_BORDERS, Cell, CellAlignment, Row as cRow,
    Table,
};
use diesel::{dsl::exists, prelude::*, sqlite::SqliteConnection};
use inquire::Text;
use models::{Almacen, NewData};
use ring::{
    aead::{self, LessSafeKey, CHACHA20_POLY1305, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};
use zeroize::Zeroize;

mod models;
mod schema;

const FILE_EXPORT: &str = "./files/exportar_datos.csv";
const FILE_IMPORT: &str = "./files/importar_datos.csv";
const DB: &str = "./private/almacen.db";

const DB_PATH: &str = "./private";
const KEY_PATH: &str = "./private/private_key.bin";

fn clear_console() {
    print!("\x1B[2J\x1B[1;1H");
}

fn lock_memory(data: &mut [u8]) {
    #[cfg(target_os = "windows")]
    unsafe {
        winapi::um::memoryapi::VirtualLock(data.as_ptr() as *mut _, data.len());
    }

    #[cfg(target_family = "unix")]
    unsafe {
        libc::mlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

fn conexion(status: bool) -> Result<SqliteConnection> {
    if status {
        fs::create_dir(DB_PATH)?;
    }
    Ok(SqliteConnection::establish(DB)?)
}

fn create_key() -> Result<()> {
    let rng = SystemRandom::new();
    let mut key_bytes = vec![0u8; CHACHA20_POLY1305.key_len()];
    rng.fill(&mut key_bytes).expect("Error create key");
    lock_memory(&mut key_bytes);
    save_key(KEY_PATH, &key_bytes)?;
    Ok(())
}

fn load_key() -> Result<LessSafeKey> {
    let mut key = Vec::new();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x80) // ATTRIBUTE: ENCRYPTED
        .open(KEY_PATH)?;

    file.read_to_end(&mut key)?;
    lock_memory(&mut key);

    let unbound_key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).expect("Error load key");

    let less_safe_key = LessSafeKey::new(unbound_key);
    Ok(less_safe_key)
}

fn save_key<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(0x80) // ATTRIBUTE: ENCRYPTED
        .open(path)?;

    file.write_all(data)?;
    Ok(())
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .expect("error fill nonce");

    let nonce =
        aead::Nonce::try_assume_unique_for_key(&nonce_bytes).expect("error construct nonce");
    let mut in_out = Vec::from(data);
    let additional_data = aead::Aad::from(b"");
    let read_key = load_key()?;

    read_key
        .seal_in_place_append_tag(nonce, additional_data, &mut in_out)
        .expect("error encrypting");

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend_from_slice(&in_out);

    Ok(encrypted_data)
}

fn add(conexion: &mut SqliteConnection, data: &Almacen) -> Result<()> {
    if !check_name(&data.nombre) {
        return Ok(());
    }

    if diesel::select(exists(
        almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&data.nombre)),
    ))
    .get_result::<bool>(conexion)?
    {
        println!("Error: Name '{}' already exist", &data.nombre);
        return Ok(());
    }

    let encrypted = encrypt_data(&data.key)?;

    diesel::insert_into(almacen_dsl::almacen)
        .values(NewData {
            nombre: &data.nombre,
            key: &encrypted,
        })
        .execute(conexion)?;

    Ok(())
}

fn view_all(conexion: &mut SqliteConnection, inicio: &u16, fin: &u16) -> Result<()> {
    let results = almacen_dsl::almacen
        .limit((fin - inicio) as i64)
        .offset(*inicio as i64)
        .load::<Almacen>(conexion)?;

    if results.is_empty() {
        println!("No hay registros en el rango especificado");
        return Ok(());
    }

    let total = results.len();
    let total_db: i64 = almacen_dsl::almacen.count().get_result(conexion)?;

    let mut tabla = Table::new();

    tabla
        .load_preset(UTF8_NO_BORDERS)
        .apply_modifier(UTF8_ROUND_CORNERS);

    tabla.set_header(vec![
        Cell::new("ID"),
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);

    let read_key = load_key()?;

    for row in results {
        let (nonce_bytes, encrypted_data) = row.key.split_at(NONCE_LEN);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(nonce_bytes).expect("error creating nonce");

        let mut data_vec = encrypted_data.to_vec();

        let decrypted = read_key
            .open_in_place(nonce, aead::Aad::from(b""), &mut data_vec)
            .expect("error decrypting");

        tabla.add_row(cRow::from(vec![
            Cell::new(row.id),
            Cell::new(row.nombre.clone()),
            Cell::new(String::from_utf8_lossy(decrypted)),
        ]));

        decrypted.zeroize();
    }

    println!("{}\n", &tabla);
    println!(
        "Mostrando registros del {} al {} - Total: {} - Total DB: {}",
        &inicio, &fin, &total, total_db
    );

    Ok(())
}

fn import_all(conexion: &mut SqliteConnection) -> Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(FILE_IMPORT)?;

    for line in reader.records() {
        let record = line?;

        if record[0].is_empty() {
            println!(
                "Error: empty name for key '{}...', skipped.",
                &record[1][0..4]
            );
            continue;
        } else if record[1].is_empty() {
            println!("Error: empty key for name: '{}', skipped.", &record[0]);
            continue;
        }

        let almacen_ = Almacen {
            id: 0,
            nombre: record[0].to_string(),
            key: record[1].as_bytes().to_vec(),
        };

        add(conexion, &almacen_)?;
    }

    println!("The data has been imported successfully.");
    Ok(())
}

fn export_all(conexion: &mut SqliteConnection) -> Result<()> {
    let results = almacen_dsl::almacen.load::<Almacen>(conexion)?;
    let mut writer = csv::Writer::from_writer(File::create(FILE_EXPORT)?);

    let read_key = load_key()?;

    for row in results {
        let (nonce_bytes, encrypted_data) = row.key.split_at(ring::aead::NONCE_LEN);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(nonce_bytes).expect("error creating nonce");

        let mut data_vec = encrypted_data.to_vec();

        let decrypted = read_key
            .open_in_place(nonce, aead::Aad::from(b""), &mut data_vec)
            .expect("error decrypting");

        writer.write_record([row.nombre.as_str(), &String::from_utf8_lossy(decrypted)])?;
        decrypted.zeroize();
    }
    println!("The data has been exported successfully.");
    Ok(())
}

fn check_name(nombre: &str) -> bool {
    if nombre.len() > 9 {
        println!(
            "Error: El nombre '{}...' excede el limite de caracteres permitidos",
            &nombre[0..9]
        );
        return false;
    }

    if !nombre.chars().all(|c| c.is_alphanumeric() || c == '_') {
        println!("Error: El nombre solo puede contener letras, numeros y guiones bajos");
        return false;
    }

    true
}

fn create_schema(conexion: &mut SqliteConnection) -> Result<()> {
    let data = "
        CREATE TABLE IF NOT EXISTS Almacen (
            id INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            key BLOB NOT NULL
        );
            
        CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
    ";

    diesel::sql_query(data).execute(conexion)?;
    Ok(())
}

fn remove(conexion: &mut SqliteConnection, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(name)))
        .execute(conexion)?;

    if rows == 0 {
        println!("No record found with name '{}'", name);
    }

    Ok(())
}

fn main() -> Result<()> {
    clear_console();

    let status = !Path::new(KEY_PATH).exists();
    let conex = &mut conexion(status)?;

    if status {
        create_schema(conex)?;
        create_key()?;
    }

    loop {
        println!(
            "{}, {}, {}, {}, {}, {} - abr{}lak{}bra",
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
            ["a", name, privkey] => {
                let mut privkey_ = privkey.as_bytes().to_vec();
                lock_memory(&mut privkey_);

                add(
                    conex,
                    &Almacen {
                        id: 0,
                        nombre: name.to_string(),
                        key: privkey_,
                    },
                )?;
            }
            ["v", inicio, fin] => {
                println!(" ");
                let pg_inicio = inicio.parse::<u16>()?;
                let pg_fin = fin.parse::<u16>()?;
                view_all(conex, &pg_inicio, &pg_fin)?;
                println!(" ");
            }
            ["e"] => {
                export_all(conex)?;
                println!(" ");
            }
            ["i"] => {
                import_all(conex)?;
                println!(" ");
            }
            ["r", _nombre] => {
                remove(conex, _nombre)?;
                println!(" ");
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
