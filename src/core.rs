use crate::schema::{almacen::dsl as almacen_dsl, usermaster::dsl as users_dsl};
use anyhow::{anyhow, Result};
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_NO_BORDERS, Cell, CellAlignment, Row as cRow,
    Table,
};
use diesel::{dsl::exists, prelude::*, sqlite::SqliteConnection};
use inquire::{Password, PasswordDisplayMode::Masked, Text};
use ring::{
    aead::{self, LessSafeKey, CHACHA20_POLY1305, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
    sync::OnceLock,
};
use zeroize::Zeroize;

mod auth;
mod constantes;
mod models;
mod schema;

pub enum Prompts {
    NewPassword,
    NewLogin,
    Init,
}

static ENCRYPTION_KEY: OnceLock<LessSafeKey> = OnceLock::new();

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
        fs::create_dir(constantes::DB_PATH)?;
    }
    Ok(SqliteConnection::establish(constantes::DB)?)
}

fn authenticate(conexion: &mut SqliteConnection, password: &str) -> Result<bool> {
    let result = users_dsl::usermaster.first::<models::User>(conexion);

    match result {
        Ok(user) => auth::verify_pwd(password, &user.hash),
        Err(_) => Ok(false),
    }
}

fn new_pwd(conexion: &mut SqliteConnection, pwd: &str) -> Result<()> {
    let hash = auth::hash_pwd(pwd)?;

    diesel::insert_into(users_dsl::usermaster)
        .values(models::NewUser { hash: &hash })
        .execute(conexion)?;
    Ok(())
}

fn prompts(p: Prompts) -> Result<String> {
    match p {
        Prompts::NewPassword => Ok(Password::new("New Password: ")
            .with_display_mode(Masked)
            .prompt()?),
        Prompts::NewLogin => Ok(Password::new("Enter Password")
            .without_confirmation()
            .prompt()?),
        Prompts::Init => Ok(Text::new("\x1b[32m->\x1b[0m").prompt()?),
    }
}

fn create_key() -> Result<()> {
    let mut key_bytes = vec![0u8; CHACHA20_POLY1305.key_len()];
    SystemRandom::new()
        .fill(&mut key_bytes)
        .map_err(|_| anyhow!("Error: Failed to generate random key"))?;

    lock_memory(&mut key_bytes);

    let mut data = Vec::new();
    data.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(&key_bytes);

    save_key(constantes::KEY_PATH, &data)?;
    Ok(())
}

fn load_key() -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x80)
        .open(constantes::KEY_PATH)?;

    let file_size = file.metadata()?.len() as usize;
    let mut buffer = vec![0u8; file_size];
    file.read_exact(&mut buffer)?;

    let key_size = u32::from_le_bytes(buffer[..4].try_into()?) as usize;
    let mut key = buffer[4..4 + key_size].to_vec();
    lock_memory(&mut key);

    auth::derive_key(&key)?;

    let unbound_key =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).expect("Error load key");
    let less_safe_key = LessSafeKey::new(unbound_key);

    ENCRYPTION_KEY
        .set(less_safe_key)
        .map_err(|_| anyhow!("Error: Failed to set encryption key"))?;

    Ok(())
}

fn save_key<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(0x80)
        .open(path)?;

    file.write_all(data)?;
    Ok(())
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("Error: Failed to generate nonce"))?;

    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| anyhow!("Error: Invalid nonce length"))?;
    let mut in_out = Vec::from(data);
    let additional_data = aead::Aad::from(b"");
    let read_key = ENCRYPTION_KEY
        .get()
        .ok_or_else(|| anyhow!("Error: Encryption key not initialized"))?;

    read_key
        .seal_in_place_append_tag(nonce, additional_data, &mut in_out)
        .map_err(|_| anyhow!("Error: Failed to encrypt data"))?;

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend_from_slice(&in_out);

    Ok(encrypted_data)
}

fn add(conexion: &mut SqliteConnection, data: &models::Almacen) -> Result<()> {
    if !check_name(&data.nombre) {
        return Ok(());
    }

    if diesel::select(exists(
        almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&data.nombre)),
    ))
    .get_result::<bool>(conexion)?
    {
        println!("Error: '{}' already exist, skipped.", &data.nombre);
        return Ok(());
    }

    let encrypted = encrypt_data(&data.key)?;

    diesel::insert_into(almacen_dsl::almacen)
        .values(models::NewData {
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
        .load::<models::Almacen>(conexion)?;

    if results.is_empty() {
        println!("Error: No records found in the specified range");
        return Ok(());
    }

    let total_db: i64 = almacen_dsl::almacen.count().get_result(conexion)?;
    let total = results.len() as u16;

    let mut tabla = Table::new();
    tabla
        .load_preset(UTF8_NO_BORDERS)
        .apply_modifier(UTF8_ROUND_CORNERS);

    tabla.set_header(vec![
        Cell::new("ID"),
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);

    let read_key = ENCRYPTION_KEY
        .get()
        .ok_or_else(|| anyhow!("Error: Encryption key not initialized"))?;

    let mut data_vec = Vec::with_capacity(28);

    for row in results {
        let (nonce_bytes, encrypted_data) = row.key.split_at(NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow!("Error: Invalid nonce in stored data"))?;

        data_vec.clear();
        data_vec.extend_from_slice(encrypted_data);

        let decrypted = read_key
            .open_in_place(nonce, aead::Aad::from(b""), &mut data_vec)
            .map_err(|_| anyhow!("Error: Failed to decrypt data"))?;

        tabla.add_row(cRow::from(vec![
            Cell::new(row.id),
            Cell::new(row.nombre.clone()),
            Cell::new(String::from_utf8_lossy(decrypted)),
        ]));

        decrypted.zeroize();
    }

    println!("{}", &tabla);
    println!(
        "Showing records from id {} to {} - Found: {} - DB Total: {}",
        &inicio, &fin, &total, total_db
    );

    Ok(())
}

fn import_all(conexion: &mut SqliteConnection) -> Result<()> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b',')
        .from_path(constantes::FILE_IMPORT)?;

    for line in reader.records() {
        let record = line?;

        if record[0].is_empty() {
            println!("Error: '{}' has no name, skipped.", &record[1][0..5]);
            continue;
        } else if record[1].is_empty() {
            println!("Error: Empty key for name: '{}', skipped.", &record[0]);
            continue;
        }

        let almacen_ = models::Almacen {
            id: 0,
            nombre: record[0].to_string(),
            key: record[1].as_bytes().to_vec(),
        };

        add(conexion, &almacen_)?;
    }

    println!("Ok.");
    Ok(())
}

fn export_all(conexion: &mut SqliteConnection) -> Result<()> {
    let results = almacen_dsl::almacen.load::<models::Almacen>(conexion)?;
    let mut writer = csv::Writer::from_writer(File::create(constantes::FILE_EXPORT)?);

    let read_key = ENCRYPTION_KEY
        .get()
        .ok_or_else(|| anyhow!("Error: Encryption key not initialized"))?;

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
    println!("Data has been exported successfully");
    Ok(())
}

fn check_name(nombre: &str) -> bool {
    if nombre.len() > 9 {
        println!(
            "Error: Name '{}...' exceeds the allowed length",
            &nombre[0..9]
        );
        return false;
    }

    if !nombre.chars().all(|c| c.is_alphanumeric() || c == '_') {
        println!("Error: Name can only contain letters, numbers and underscores");
        return false;
    }

    true
}

fn create_schema(conexion: &mut SqliteConnection) -> Result<()> {
    let almacen_schema = "
        CREATE TABLE IF NOT EXISTS Almacen (
            id INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            key BLOB NOT NULL
        );
            
        CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
    ";

    diesel::sql_query(almacen_schema).execute(conexion)?;

    let users_schema = "
        CREATE TABLE IF NOT EXISTS usermaster (
            hash TEXT NOT NULL UNIQUE PRIMARY KEY
        );
    ";

    diesel::sql_query(users_schema).execute(conexion)?;
    Ok(())
}

fn remove(conexion: &mut SqliteConnection, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&name)))
        .execute(conexion)?;

    if rows == 0 {
        println!("Error: No record found with name '{}'", &name);
        return Ok(());
    }

    println!("'{}' has been successfully deleted", &name);
    Ok(())
}

pub fn init() -> Result<()> {
    print!("\x1B[2J\x1B[1;1H");

    let status = !Path::new(constantes::KEY_PATH).exists();
    let conex = &mut conexion(status)?;

    if status {
        create_schema(conex)?;
        create_key()?;

        println!("New Password\n");

        let password = prompts(Prompts::NewPassword)?;

        new_pwd(conex, &password)?;
    } else {
        println!("Login\n");

        let mut authenticated = false;

        while !authenticated {
            let password = prompts(Prompts::NewLogin)?;

            match authenticate(conex, &password)? {
                true => {
                    authenticated = true;
                }
                false => {
                    println!("Error: Wrong password\n");
                }
            }
        }
    }

    load_key()?;
    print!("\x1B[2J\x1B[1;1H");

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

        let entrada = prompts(Prompts::Init)?;
        let partes: Vec<&str> = entrada.split_whitespace().collect();

        match partes.as_slice() {
            ["a", name, privkey] => {
                add(
                    conex,
                    &models::Almacen {
                        id: 0,
                        nombre: name.to_string(),
                        key: privkey.as_bytes().to_vec(),
                    },
                )?;
                println!("Ok.\n");
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
                print!("\x1B[2J\x1B[1;1H");
            }
        }
    }
    Ok(())
}
