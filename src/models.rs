use crate::schema::almacen;
use crate::schema::almacen_data;
use crate::schema::recovery;
use diesel::prelude::*;

#[derive(Queryable)]
#[diesel(table_name = almacen)]
pub struct Almacen {
    pub id: i32,
    pub nombre: String,
    pub key: String,
}

#[derive(Insertable)]
#[diesel(table_name = almacen)]
pub struct NewRegistro<'a> {
    pub nombre: &'a str,
    pub key: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = almacen_data)]
pub struct NewData<'a> {
    pub key: &'a str,
    pub nonce: &'a str,
}

#[derive(Insertable)]
#[diesel(table_name = recovery)]
pub struct NewRecovery<'a> {
    pub salt: &'a str,
    pub hash: &'a str,
}