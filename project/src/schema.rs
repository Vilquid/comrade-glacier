// @generated automatically by Diesel CLI.

diesel::table! {
    domains (id) {
        id -> Int8,
        domain -> Text,
        bimi -> Jsonb,
        certificate -> Jsonb,
        dane -> Jsonb,
        dmarc -> Jsonb,
        mta -> Jsonb,
        tls_rpt -> Jsonb,
        spf -> Jsonb,
    }
}

diesel::table! {
    ports (id) {
        id -> Int8,
        ip -> Text,
        port_25_open -> Bool,
        domain -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    domains,
    ports,
);
