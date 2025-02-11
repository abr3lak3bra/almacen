use crate::schema::almacen;
use crate::schema::recovery;
use diesel::prelude::*;

#[derive(Queryable)]
#[diesel(table_name = almacen)]
pub struct Almacen {
    #[warn(dead_code)]
    pub id: i32,
    pub nombre: String,
    pub key: String,
}

#[derive(Insertable)]
#[diesel(table_name = almacen)]
pub struct Registro<'a> {
    pub nombre: &'a str,
    pub key: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = recovery)]
pub struct RegistroRecovery<'a> {
    pub salt: &'a str,
    pub hash: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = recovery)]
pub struct StatusRecovery<'a> {
    pub status: &'a bool,
}
