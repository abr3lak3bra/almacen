// @generated automatically by Diesel CLI.

diesel::table! {
    almacen (id) {
        id -> Integer,
        nombre -> Text,
        key -> Text,
    }
}

diesel::table! {
    almacen_data (id) {
        id -> Integer,
        key -> Text,
        nonce -> Text,
    }
}

diesel::table! {
    recovery (id) {
        id -> Integer,
        hash -> Text,
        salt -> Text,
    }
}