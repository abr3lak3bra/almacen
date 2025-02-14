use crate::models::{Almacen, NewData, NewRecovery, NewRegistro};
use crate::schema::almacen::dsl as almacen_dsl;
use crate::schema::almacen_data::dsl as almacen_data_dsl;
use crate::schema::recovery::dsl as recovery_dsl;
use anyhow::{anyhow, bail, Ok, Result};
use argon2::{password_hash::SaltString, Argon2};
use base64::prelude::*;
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_NO_BORDERS, Cell, CellAlignment, Row as cRow,
    Table,
};
use diesel::{dsl::exists, prelude::*, sqlite::SqliteConnection};
use inquire::Text;
use ring::{
    aead::{
        Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
        NONCE_LEN,
    },
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    env,
    fs::{self, File},
    path::Path,
};
use zeroize::Zeroize;

mod models;
mod schema;

struct SingleNonce([u8; NONCE_LEN]);

struct Data {
    s_master: String,
    s_salt: SaltString,
}

struct Conexion {
    pool: SqliteConnection,
}

const DB: &str = "./db/db.db";
const DB_PATH: &str = "./db";
const FILE_EXPORT: &str = "./files/exportar_datos.csv";
const FILE_IMPORT: &str = "./files/importar_datos.csv";

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Nonce::try_assume_unique_for_key(&self.0)
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        self.s_master.zeroize();
    }
}

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

impl Default for Data {
    fn default() -> Self {
        let rand = SystemRandom::new();
        let master = env::var("PWD").unwrap();

        let mut salt_value = [0; 32];
        rand.fill(&mut salt_value).unwrap();

        Self::new(master, SaltString::encode_b64(&salt_value).unwrap())
    }
}

impl Data {
    fn new(_master: String, salt_: SaltString) -> Self {
        Self {
            s_master: _master,
            s_salt: salt_,
        }
    }

    fn new_hash(&self, salt: String) -> Result<String> {
        let mut new_hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                self.s_master.as_bytes(),
                salt.to_string().as_bytes(),
                &mut new_hash,
            )
            .map_err(|err| anyhow!("Error hashing: {}", err))?;
        Ok(BASE64_URL_SAFE.encode(new_hash))
    }

    fn new_instance(&self, salt: String, conexion: &mut Conexion) -> Result<()> {
        let new_hash = self.new_hash(salt)?;

        diesel::insert_into(recovery_dsl::recovery)
            .values(NewRecovery {
                salt: self.s_salt.as_str(),
                hash: &new_hash,
            })
            .execute(&mut conexion.pool)?;

        Ok(())
    }

    fn get_salt_hash_from_db(conexion: &mut Conexion) -> Result<(String, String)> {
        let result = recovery_dsl::recovery
            .select((recovery_dsl::salt, recovery_dsl::hash))
            .first::<(String, String)>(&mut conexion.pool)
            .map_err(|err| anyhow!("Error obtaining salt_hash from db: {}", err))?;
        Ok(result)
    }

    fn verify_hash(hash_new: &str, hash_db: &str) -> Result<()> {
        let hash_db_bytes = BASE64_URL_SAFE.decode(hash_db)?;
        let hash_new_bytes = BASE64_URL_SAFE.decode(hash_new)?;

        if hash_new_bytes != hash_db_bytes {
            bail!("Password verification failed");
        }

        Ok(())
    }
}

fn create_schema(conexion: &mut Conexion, init: bool) -> Result<()> {
    if init {
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS Recovery (
                status BOOL PRIMARY KEY DEFAULT FALSE,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
        ",
        )
        .execute(&mut conexion.pool)?;
    } else {
        let data = "
            CREATE TABLE IF NOT EXISTS Almacen (
                id INTEGER PRIMARY KEY,
                nombre TEXT NOT NULL,
                key TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS id_nombre ON Almacen(nombre);
            CREATE INDEX IF NOT EXISTS id_key ON Almacen(key);
        ";

        let data2 = "
            CREATE TABLE IF NOT EXISTS Almacen_Data (
                id INTEGER PRIMARY KEY,
                key TEXT NOT NULL,
                nonce TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS id_key ON AlmacenData(id);
        ";

        diesel::sql_query(data).execute(&mut conexion.pool)?;
        diesel::sql_query(data2).execute(&mut conexion.pool)?;
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

fn crypt(conexion: &mut Conexion, associated_data: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let rand = SystemRandom::new();
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];

    rand.fill(&mut key_bytes).expect("msg1");
    let mut nonce_value = [0; NONCE_LEN];
    rand.fill(&mut nonce_value).expect("msg2");

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).expect("err1");
    let nonce_sequence = SingleNonce(nonce_value);
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = data.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::from(associated_data), &mut in_out)
        .expect("err2");

    insert_record(&key_bytes, &nonce_value, conexion).expect("err3");

    Ok([in_out, tag.as_ref().to_vec()].concat())
}

fn decrypt(
    key_bytes: &[u8],
    nonce_value: &[u8],
    associated_data: &[u8],
    cypher_text_with_tag: &[u8],
) -> Result<Vec<u8>> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes).expect("err1");
    let nonce_sequence = SingleNonce(nonce_value.try_into()?);
    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

    let mut in_out = cypher_text_with_tag.to_vec();
    let decrypted_data = opening_key
        .open_in_place(Aad::from(associated_data), &mut in_out)
        .expect("err2");

    Ok(decrypted_data.to_vec())
}

fn decrypt_this(nombre: &String, hash: String, conexion: &mut Conexion) -> Result<Vec<u8>> {
    let (key_almacen, id) = get_key_id_almacen_from_db(conexion, nombre).expect("ee1");
    let (key, nonce) = get_key_nonce_almacendata_from_db(conexion, id).expect("ee2");

    let decode_key = BASE64_URL_SAFE.decode(&key_almacen)?.to_vec();
    let key_decoded = BASE64_URL_SAFE.decode(&key).expect("ee3");
    let nonce_decoded = BASE64_URL_SAFE.decode(&nonce).expect("ee4");

    let decrypted_data = decrypt(&key_decoded, &nonce_decoded, hash.as_bytes(), &decode_key)?;

    Ok(decrypted_data)
}

fn add(conexion: &mut Conexion, data: &Almacen) -> Result<()> {
    check_name(&data.nombre)?;

    if diesel::select(exists(
        almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(&data.nombre)),
    ))
    .get_result::<bool>(&mut conexion.pool)?
    {
        bail!("Name {} already exist", &data.nombre);
    }

    let (_, hash_db) = Data::get_salt_hash_from_db(conexion)?;
    let wrapped = crypt(conexion, hash_db.as_bytes(), data.key.as_bytes())?;

    diesel::insert_into(almacen_dsl::almacen)
        .values(NewRegistro {
            nombre: &data.nombre,
            key: &BASE64_URL_SAFE.encode(&wrapped),
        })
        .execute(&mut conexion.pool)?;

    Ok(())
}

fn remove(conexion: &mut Conexion, name: &str) -> Result<()> {
    let rows = diesel::delete(almacen_dsl::almacen.filter(almacen_dsl::nombre.eq(name)))
        .execute(&mut conexion.pool)?;

    if rows == 0 {
        bail!("No record found with name {}", name);
    }

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
        Cell::new("ID"),
        Cell::new("Nombre"),
        Cell::new("Key").set_alignment(CellAlignment::Center),
    ]);

    let (_, hash_db) = Data::get_salt_hash_from_db(conexion)?;

    for row in results {
        let decrypted = decrypt_this(&row.nombre, hash_db.clone(), conexion)?;

        tabla.add_row(cRow::from(vec![
            Cell::new(row.id),
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

    let (_, hash_db) = Data::get_salt_hash_from_db(conexion)?;

    for row in results {
        let decrypted = decrypt_this(&row.nombre, hash_db.clone(), conexion)?;
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

        let _almacen = Almacen {
            id: 0,
            nombre: record[0].to_string(),
            key: record[1].to_string(),
        };

        add(conexion, &_almacen)?;
    }

    Ok(())
}

fn insert_record(key_bytes: &[u8], nonce_value: &[u8], conexion: &mut Conexion) -> Result<()> {
    diesel::insert_into(almacen_data_dsl::almacen_data)
        .values(NewData {
            key: &BASE64_URL_SAFE.encode(key_bytes),
            nonce: &BASE64_URL_SAFE.encode(nonce_value),
        })
        .execute(&mut conexion.pool)?;
    Ok(())
}

fn get_key_id_almacen_from_db(conexion: &mut Conexion, nombre: &String) -> Result<(String, u16)> {
    let result = almacen_dsl::almacen
        .filter(almacen_dsl::nombre.eq(nombre))
        .select((almacen_dsl::id, almacen_dsl::key))
        .first::<(i32, String)>(&mut conexion.pool)?;

    let (id, key) = result;

    Ok((key, id as u16))
}

fn get_key_nonce_almacendata_from_db(conexion: &mut Conexion, id: u16) -> Result<(String, String)> {
    let result = almacen_data_dsl::almacen_data
        .filter(almacen_data_dsl::id.eq(id as i32))
        .select((almacen_data_dsl::key, almacen_data_dsl::nonce))
        .first::<(String, String)>(&mut conexion.pool)?;

    Ok(result)
}

fn main() -> Result<()> {
    clear_console();
    dotenvy::dotenv()?;

    let mut conexion = Conexion::new()?;

    create_schema(&mut conexion, true)?;

    let status_ = status(&mut conexion)?; // mejor escribirlo en un archivo?
    let data = Data::default();

    if !status_ {
        data.new_instance(data.s_salt.to_string(), &mut conexion)?;
        diesel::sql_query("UPDATE Recovery SET status = TRUE").execute(&mut conexion.pool)?;
    } else {
        let (salt_db, hash_db) = Data::get_salt_hash_from_db(&mut conexion)?;
        let new_hash = data.new_hash(salt_db)?;
        Data::verify_hash(&new_hash, &hash_db)?;
    }

    let colored = "\x1b[32m->\x1b[0m".to_string();
    let mut is_new: bool = !status_;

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

        let entrada: String = if is_new {
            Text::new(&colored).with_default("First Time: s").prompt()?
        } else {
            Text::new(&colored).prompt()?
        };

        let partes: Vec<&str> = entrada.split_whitespace().collect();

        match partes.as_slice() {
            ["s"] => {
                create_schema(&mut conexion, false)?;
                is_new = false;
                clear_console();
            }
            ["a", name, privkey] => {
                add(
                    &mut conexion,
                    &Almacen {
                        id: 0,
                        nombre: name.to_string(),
                        key: privkey.to_string(),
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
