// @generated automatically by Diesel CLI.

diesel::table! {
    almacen (id) {
        id -> Integer,
        nombre -> Text,
        key -> Binary,
    }
}

diesel::table! {
    usermaster (hash) {
        hash -> Text,
    }
}
