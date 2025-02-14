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
    recovery (status) {
        status -> Bool,
        hash -> Text,
        salt -> Text,
    }
}