use anyhow::{bail, Ok, Result};
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_NO_BORDERS, Cell, CellAlignment, Row as cRow,
    Table,
};
use diesel::{dsl::exists, prelude::*, sqlite::SqliteConnection};
use inquire::Text;
use ring::{
    aead,
    aead::{LessSafeKey, Nonce},
    rand::{SecureRandom, SystemRandom},
};
use std::os::windows::fs::OpenOptionsExt;
use std::{
    fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroize;
mod models;
mod schema;
use crate::schema::almacen::dsl as almacen_dsl;
use models::{Almacen, NewData};

const DB: &str = "./private/almacen.db";
const DB_PATH: &str = "./private";
const KEY_PATH: &str = "./private/private_key.bin";
const FILE_EXPORT: &str = "./files/exportar_datos.csv";
const FILE_IMPORT: &str = "./files/importar_datos.csv";

#[derive(Zeroize)]
struct SensitiveData {
    key: Vec<u8>,
    decrypted_data: Vec<u8>,
}

impl Drop for SensitiveData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn clear_console() {
    print!("\x1B[2J\x1B[1;1H");
}

fn conexion(status: bool) -> Result<SqliteConnection> {
    if status {
        fs::create_dir(DB_PATH)?;
    }
    Ok(SqliteConnection::establish(DB)?)
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

fn encrypt_data(data: &[u8], key: &aead::LessSafeKey) -> Result<Vec<u8>> {
    let nonce = aead::Nonce::assume_unique_for_key([0; 12]);
    let mut in_out = Vec::from(data);
    let additional_data = aead::Aad::from(b"");
    key.seal_in_place_append_tag(nonce, additional_data, &mut in_out)
        .expect("error encrypting");
    Ok(in_out)
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

fn add(conexion: &mut SqliteConnection, key: &LessSafeKey, data: &Almacen) -> Result<()> {
    check_name(&data.nombre)?;

    if diesel::select(exists(
        almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&data.nombre)),
    ))
    .get_result::<bool>(conexion)?
    {
        bail!("Name {} already exist", &data.nombre);
    }

    let encrypted = encrypt_data(&data.key, key)?;

    diesel::insert_into(almacen_dsl::almacen)
        .values(NewData {
            nombre: &data.nombre,
            key: &encrypted,
        })
        .execute(conexion)?;

    Ok(())
}

fn remove(conexion: &mut SqliteConnection, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(name)))
        .execute(conexion)?;

    if rows == 0 {
        bail!("No record found with name {}", name);
    }

    Ok(())
}

fn create_key() -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let key_len = aead::CHACHA20_POLY1305.key_len();
    let mut key_bytes = vec![0u8; key_len];
    rng.fill(&mut key_bytes).unwrap();
    save_key(KEY_PATH, &key_bytes)?;

    // Lock pages in memory to prevent swapping
    #[cfg(target_os = "windows")]
    unsafe {
        winapi::um::memoryapi::VirtualLock(key_bytes.as_ptr() as *mut _, key_bytes.len());
    }

    #[cfg(target_family = "unix")]
    unsafe {
        libc::mlock(key_bytes.as_ptr() as *const libc::c_void, key_bytes.len());
    }
    Ok(key_bytes)
}

fn load_key() -> Result<Vec<u8>> {
    let mut key = Vec::new();
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x80) // ATTRIBUTE: ENCRYPTED
        .open(KEY_PATH)?;

    file.read_to_end(&mut key)?;
    Ok(key)
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

fn view_all(
    conexion: &mut SqliteConnection,
    key: &LessSafeKey,
    inicio: &u16,
    fin: &u16,
) -> Result<()> {
    let results = almacen_dsl::almacen
        .limit((fin - inicio) as i64)
        .offset(*inicio as i64)
        .load::<Almacen>(conexion)?;

    if results.is_empty() {
        bail!("No hay registros en el rango especificado");
    }

    let total = results.len();
    let mut tabla = Table::new();

    tabla
        .load_preset(UTF8_NO_BORDERS)
        .apply_modifier(UTF8_ROUND_CORNERS);

    tabla.set_header(vec![
        Cell::new("ID"),
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);

    for row in results {
        let mut sensitive = SensitiveData {
            key: row.key.clone(),
            decrypted_data: Vec::new(),
        };

        let decrypted = key
            .open_in_place(
                Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(b""),
                &mut sensitive.key,
            )
            .expect("error decrypting");

        sensitive.decrypted_data = decrypted.to_vec();

        tabla.add_row(cRow::from(vec![
            Cell::new(row.id),
            Cell::new(row.nombre),
            Cell::new(String::from_utf8_lossy(&sensitive.decrypted_data)),
        ]));
    }

    println!("{}\n", &tabla);
    println!(
        "Mostrando registros del {} al {} - Total: {}",
        &inicio, &fin, &total
    );

    Ok(())
}

fn import_all(conexion: &mut SqliteConnection, key: &LessSafeKey) -> Result<()> {
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

        let _almacen = Almacen {
            id: 0,
            nombre: record[0].to_string(),
            key: record[1].as_bytes().to_vec(),
        };

        add(conexion, key, &_almacen)?;
    }

    Ok(())
}

fn export_all(conexion: &mut SqliteConnection, key: &LessSafeKey) -> Result<()> {
    let results = almacen_dsl::almacen.load::<Almacen>(conexion)?;

    let mut writer = csv::Writer::from_writer(File::create(FILE_EXPORT)?);

    for mut row in results {
        let decrypted = key
            .open_in_place(
                Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(b""),
                &mut row.key,
            )
            .expect("error decrypting");

        let decrypted_ = decrypted.to_vec();

        writer.write_record([
            row.nombre.as_str(),
            String::from_utf8_lossy(&decrypted_).as_ref(),
        ])?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let status = !Path::new(KEY_PATH).exists();
    let conex = &mut conexion(status)?;

    let key = {
        if status {
            create_schema(conex)?;
            create_key()?
        } else {
            load_key()?
        }
    };

    let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
    let less_safe_key = LessSafeKey::new(unbound_key);

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
                add(
                    conex,
                    &less_safe_key,
                    &Almacen {
                        id: 0,
                        nombre: name.to_string(),
                        key: privkey.as_bytes().to_vec(),
                    },
                )?;

                clear_console();
            }
            ["v", inicio, fin] => {
                clear_console();
                println!(" ");
                let pg_inicio = inicio.parse::<u16>()?;
                let pg_fin = fin.parse::<u16>()?;
                view_all(conex, &less_safe_key, &pg_inicio, &pg_fin)?;
                println!(" ");
            }
            ["e"] => {
                export_all(conex, &less_safe_key)?;
                clear_console();
            }
            ["i"] => {
                import_all(conex, &less_safe_key)?;
                clear_console();
            }
            ["r", _nombre] => {
                remove(conex, _nombre)?;
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