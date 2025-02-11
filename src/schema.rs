// @generated automatically by Diesel CLI.

diesel::table! {
    almacen (id) {
        id -> Integer,
        nombre -> Text,
        key -> Text,
    }
}

diesel::table! {
    recovery (status) {
        status -> Bool,
        hash -> Text,
        salt -> Text,
    }
}