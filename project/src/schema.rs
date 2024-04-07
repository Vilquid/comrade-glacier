// @generated automatically by Diesel CLI.


diesel::table! {
    domains (id) {
        id -> Int8,
        domain -> Text,
        bimi_used -> Bool,
        bimi_version -> Text,
		bimi_url_sender -> Text,
		bimi_url_policy -> Text,
        bimi_url_reputation -> Text,
        bimi_hash -> Text,
        bimi_s -> Text,
        certificate_used -> Bool,
        certificate_signature_algorithm_server -> Text,
        certificate_issuer_server_city -> Text,
        certificate_issuer_server_state -> Text,
        certificate_issuer_server_locality -> Text,
        certificate_issuer_server_organization -> Text,
        certificate_issuer_server_common_name -> Text,
        certificate_validity_server_not_before -> Text,
        certificate_validity_server_not_after -> Text,
        certificate_validity_server_is_valid -> Bool,
        certificate_subject_server_city -> Text,
        certificate_subject_server_state -> Text,
        certificate_subject_server_locality -> Text,
        certificate_subject_server_organization -> Text,
        certificate_subject_server_common_name -> Text,
        certificate_extensions_server_subject_alternative_names -> Array<Text>,
        certificate_signature_algorithm_intermediate -> Text,
        certificate_issuer_intermediate_city -> Text,
        certificate_issuer_intermediate_state -> Text,
        certificate_issuer_intermediate_locality -> Text,
        certificate_issuer_intermediate_organization -> Text,
        certificate_issuer_intermediate_common_name -> Text,
        certificate_validity_intermediate_not_before -> Text,
        certificate_validity_intermediate_not_after -> Text,
        certificate_subject_intermediate_city -> Text,
        certificate_subject_intermediate_state -> Text,
        certificate_subject_intermediate_locality -> Text,
        certificate_subject_intermediate_organization -> Text,
        certificate_subject_intermediate_common_name -> Text,
        certificate_extensions_intermediate_subject_alternative_names -> Array<Text>,
        dane_used -> Bool,
        dane_certificate_shape -> Int4,
        dane_certificate_signature -> Bool,
        dane_hash_presence -> Bool,
        dane_hash -> Text,
        dane_public_key_signature -> Bool,
        dmarc_used -> Bool,
        dmarc_v -> Text,
        dmarc_adkim -> Text,
        dmarc_aspf -> Text,
        dmarc_fo -> Text,
        dmarc_p -> Text,
        dmarc_pct -> Int4,
        dmarc_sp -> Text,
        dmarc_rf -> Text,
        dmarc_ri -> Text,
        dmarc_rua -> Text,
        dmarc_ruf -> Text,
        mta_used -> Bool,
        mta_version -> Text,
        mta_sn -> Text,
        spf_used -> Bool,
        spf_version -> Text,
        spf_mechanisms -> Array<Text>,
        spf_qualifier -> Text,
        spf_ip -> Array<Text>,
        spf_include -> Array<Text>,
        spf_all -> Text,
        tls_rpt_used -> Bool,
        tls_rpt_v -> Text,
        tls_rpt_rua -> Text,
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
