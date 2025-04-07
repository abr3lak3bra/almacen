use crate::schema::almacen;
use crate::schema::usermaster;
use diesel::prelude::*;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop, Queryable)]
#[diesel(table_name = almacen)]
pub struct Almacen {
    pub id: i32,
    pub nombre: String,
    pub key: Vec<u8>,
}

#[derive(Queryable)]
#[diesel(table_name = usermaster)]
pub struct User {
    pub hash: String,
}

#[derive(Insertable)]
#[diesel(table_name = almacen)]
pub struct NewData<'a> {
    pub nombre: &'a str,
    pub key: &'a [u8],
}

#[derive(Insertable)]
#[diesel(table_name = usermaster)]
pub struct NewUser<'a> {
    pub hash: &'a str,
}
