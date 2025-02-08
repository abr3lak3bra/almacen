use crate::schema::almacen;
use diesel::prelude::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = almacen)]
pub struct Almacen {
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
