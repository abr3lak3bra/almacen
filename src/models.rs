use crate::schema::almacen;
use diesel::prelude::*;

#[derive(Queryable)]
#[diesel(table_name = almacen)]
pub struct Almacen {
    pub id: i32,
    pub nombre: String,
    pub key: Vec<u8>,
}

#[derive(Insertable)]
#[diesel(table_name = almacen)]
pub struct NewData<'a> {
    pub nombre: &'a str,
    pub key: &'a [u8],
}