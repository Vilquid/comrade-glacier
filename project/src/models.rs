use std::fmt::Debug;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use crate::schema::*;
use diesel::{Insertable, QueryId};
use diesel::expression::Expression;


/// # Brief
/// Model for the `ports` table in the database.
/// # Attributes
/// - derive(Queryable, Selectable)
/// - diesel(table_name = crate::schema::ports)
/// - diesel(check_for_backend(diesel::pg::Pg))
/// # Fields
/// - `id` *u64* - The unique identifier for the line
/// - `ip` *Ipv4Addr* - The IP address of the server
/// - `port_25_open` *bool* - Whether port 25 is open
/// - `domain` *String* - The domain name of the server
#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::ports)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Port
{
	pub id: i64,
	pub ip: String,
	pub port_25_open: bool,
	pub domain: String,
}

/// # Brief
/// Structure to insert in the `ports` table
/// # Attributes
/// - derive(Insertable)
/// - diesel(table_name = ports)
/// # Fields
/// - `ip` *Ipv4Addr* - The IP address of the server
/// - `port_25_open` *bool* - Whether port 25 is open
/// - `domain` *String* - The domain name of the server
#[derive(Insertable)]
#[diesel(table_name = ports)]
pub struct NewPort
{
	pub ip: String,
	pub port_25_open: bool,
	pub domain: String,
}

/// # Brief
/// Model for the `domains` table in the database.
/// # Attributes
/// - derive(Queryable, Selectable)
/// - diesel(table_name = crate::schema::domains)
/// - diesel(check_for_backend(diesel::pg::Pg))
/// # Fields
/// - `id` *u64* - The unique identifier of `domain`
/// - `domain` *String* - The domain name
/// - `bimi_used` *bool* : Whether the bimi record is used
/// - `bimi_version` *String* : current version of bimi protocol
/// - `bimi_url_sender` *String* : The URL where the sender's logo (image) is hosted
/// - `bimi_url_policy` *String* : URL where the sender's bimi policy is published
/// - `bimi_url_reputation` *String* : URL linked to a reputation service providing information about the sender's reliability and legitimacy
/// - `bimi_hash` *String* : Hash of the sender's image
/// - `bimi_s` *String* : Signature of the sender's image
/// - `dane_used` *bool* : Whether the dane record is used
/// - `dane_certificate_shape` *i32* : Shape of the certificate
/// - `dane_certificate_signature` *bool* : Whether the certificate is signed
/// - `dane_hash_presence` *bool* : Whether a hash is present
/// - `dane_hash` *String* : The hash of the certificate
/// - `dane_public_key_signature` *bool* : Whether the public key is signed
/// - `dmarc_used` *bool* : Whether the dmarc record is used
/// - `dmarc_v` *String* : Version of dmarc protocol
/// - `dmarc_adkim` *String* : Alignment mode for dkmin
/// - `dmarc_aspf` *String* : Alignment mode for spf
/// - `dmarc_fo` *String* : Reporting fails of options
/// - `dmarc_p` *String* : Requested policy
/// - `dmarc_pct` *i16* : Percentage of messages subjected  to applying the dmarc policy
/// - `dmarc_sp` *String* : Requested policy for subdomains
/// - `dmarc_rf` *String* : Format to use for reports of specific legal informations about the message
/// - `dmarc_ri` *String* : Interval in seconds between aggregate reports
/// - `dmarc_rua` *String* : URL to which aggregate reports are sent
/// - `dmarc_ruf` *String* : URL to which reports of failures are sent
/// - `mta_used` *bool* : Whether the mta-sts record is used
/// - `mta_version` *String* : version of mta-sts
/// - `mta_sn` *String* : serial number
/// - `tls_rpt_used` *bool* : Whether the tls record is used
/// - `tls_rpt_v` *String* : Version of tls-rpt
/// - `tls_rpt_rua` *String* : URL to which reports are sent
/// # Comments
/// La doc pour la partie certificat n'est pas implémentée pour le moment
#[derive(Queryable, Selectable, QueryId)]
#[diesel(table_name = crate::schema::domains)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Domain
{
	pub id: i64,
	pub domain: String,
	pub bimi_used: bool,
	pub bimi_version: String,
	pub bimi_url_sender: String,
	pub bimi_url_policy: String,
	pub bimi_url_reputation: String,
	pub bimi_hash: String,
	pub bimi_s: String,
	pub certificate_used: bool,
	pub certificate_signature_algorithm_server: String,
	pub certificate_issuer_server_city: String,
	pub certificate_issuer_server_state: String,
	pub certificate_issuer_server_locality: String,
	pub certificate_issuer_server_organization: String,
	pub certificate_issuer_server_common_name: String,
	pub certificate_validity_server_not_before: String,
	pub certificate_validity_server_not_after: String,
	pub certificate_validity_server_is_valid: bool,
	pub certificate_subject_server_city: String,
	pub certificate_subject_server_state: String,
	pub certificate_subject_server_locality: String,
	pub certificate_subject_server_organization: String,
	pub certificate_subject_server_common_name: String,
	pub certificate_extensions_server_subject_alternative_names: Vec<String>,
	pub certificate_signature_algorithm_intermediate: String,
	pub certificate_issuer_intermediate_city: String,
	pub certificate_issuer_intermediate_state: String,
	pub certificate_issuer_intermediate_locality: String,
	pub certificate_issuer_intermediate_organization: String,
	pub certificate_issuer_intermediate_common_name: String,
	pub certificate_validity_intermediate_not_before: String,
	pub certificate_validity_intermediate_not_after: String,
	pub certificate_subject_intermediate_city: String,
	pub certificate_subject_intermediate_state: String,
	pub certificate_subject_intermediate_locality: String,
	pub certificate_subject_intermediate_organization: String,
	pub certificate_subject_intermediate_common_name: String,
	pub certificate_extensions_intermediate_subject_alternative_names: Vec<String>,
	pub dane_used: bool,
	pub dane_certificate_shape: i32,
	pub dane_certificate_signature: bool,
	pub dane_hash_presence: bool,
	pub dane_hash: String,
	pub dane_public_key_signature: bool,
	pub dmarc_used: bool,
	pub dmarc_v: String,
	pub dmarc_adkim: String,
	pub dmarc_aspf: String,
	pub dmarc_fo: String,
	pub dmarc_p: String,
	pub dmarc_pct: i32,
	pub dmarc_sp: String,
	pub dmarc_rf: String,
	pub dmarc_ri: String,
	pub dmarc_rua: String,
	pub dmarc_ruf: String,
	pub mta_used: bool,
	pub mta_version: String,
	pub mta_sn: String,
	pub spf_used: bool,
	pub spf_version: String,
	pub spf_mechanisms: Vec<String>,
	pub spf_qualifier: String,
	pub spf_ip: Vec<String>,
	pub spf_include: Vec<String>,
	pub spf_all: String,
	pub tls_rpt_used: bool,
	pub tls_rpt_v: String,
	pub tls_rpt_rua: String,
}

/// # Brief
/// Model for the `domains` table in the database.
/// # Attributes
/// - derive(Insertable)
/// - diesel(table_name = domains)
/// # Fields
/// - `domain` *String* - The domain name
/// - `bimi_used` *bool* : Whether the bimi record is used
/// - `bimi_version` *String* : current version of bimi protocol
/// - `bimi_url_sender` *String* : The URL where the sender's logo (image) is hosted
/// - `bimi_url_policy` *String* : URL where the sender's bimi policy is published
/// - `bimi_url_reputation` *String* : URL linked to a reputation service providing information about the sender's reliability and legitimacy
/// - `bimi_hash` *String* : Hash of the sender's image
/// - `bimi_s` *String* : Signature of the sender's image
/// - `dane_used` *bool* : Whether the dane record is used
/// - `dane_certificate_shape` *i32* : Shape of the certificate
/// - `dane_certificate_signature` *bool* : Whether the certificate is signed
/// - `dane_hash_presence` *bool* : Whether a hash is present
/// - `dane_hash` *String* : The hash of the certificate
/// - `dane_public_key_signature` *bool* : Whether the public key is signed
/// - `dmarc_used` *bool* : Whether the dmarc record is used
/// - `dmarc_v` *String* : Version of dmarc protocol
/// - `dmarc_adkim` *String* : Alignment mode for dkmin
/// - `dmarc_aspf` *String* : Alignment mode for spf
/// - `dmarc_fo` *String* : Reporting fails of options
/// - `dmarc_p` *String* : Requested policy
/// - `dmarc_pct` *i16* : Percentage of messages subjected  to applying the dmarc policy
/// - `dmarc_sp` *String* : Requested policy for subdomains
/// - `dmarc_rf` *String* : Format to use for reports of specific legal informations about the message
/// - `dmarc_ri` *String* : Interval in seconds between aggregate reports
/// - `dmarc_rua` *String* : URL to which aggregate reports are sent
/// - `dmarc_ruf` *String* : URL to which reports of failures are sent
/// - `mta_used` *bool* : Whether the mta-sts record is used
/// - `mta_version` *String* : version of mta-sts
/// - `mta_sn` *String* : serial number
/// - `tls_rpt_used` *bool* : Whether the tls record is used
/// - `tls_rpt_v` *String* : Version of tls-rpt
/// - `tls_rpt_rua` *String* : URL to which reports are sent
/// # Comments
/// La doc pour la partie certificat n'est pas implémentée pour le moment
#[derive(Insertable, QueryId)]
#[diesel(table_name = domains)]
pub struct NewDomain
{
	pub domain: String,
	pub bimi_used: bool,
	pub bimi_version: String,
	pub bimi_url_sender: String,
	pub bimi_url_policy: String,
	pub bimi_url_reputation: String,
	pub bimi_hash: String,
	pub bimi_s: String,
	pub certificate_used: bool,
	pub certificate_signature_algorithm_server: String,
	pub certificate_issuer_server_city: String,
	pub certificate_issuer_server_state: String,
	pub certificate_issuer_server_locality: String,
	pub certificate_issuer_server_organization: String,
	pub certificate_issuer_server_common_name: String,
	pub certificate_validity_server_not_before: String,
	pub certificate_validity_server_not_after: String,
	pub certificate_validity_server_is_valid: bool,
	pub certificate_subject_server_city: String,
	pub certificate_subject_server_state: String,
	pub certificate_subject_server_locality: String,
	pub certificate_subject_server_organization: String,
	pub certificate_subject_server_common_name: String,
	pub certificate_extensions_server_subject_alternative_names: Vec<String>,
	pub certificate_signature_algorithm_intermediate: String,
	pub certificate_issuer_intermediate_city: String,
	pub certificate_issuer_intermediate_state: String,
	pub certificate_issuer_intermediate_locality: String,
	pub certificate_issuer_intermediate_organization: String,
	pub certificate_issuer_intermediate_common_name: String,
	pub certificate_validity_intermediate_not_before: String,
	pub certificate_validity_intermediate_not_after: String,
	pub certificate_subject_intermediate_city: String,
	pub certificate_subject_intermediate_state: String,
	pub certificate_subject_intermediate_locality: String,
	pub certificate_subject_intermediate_organization: String,
	pub certificate_subject_intermediate_common_name: String,
	pub certificate_extensions_intermediate_subject_alternative_names: Vec<String>,
	pub dane_used: bool,
	pub dane_certificate_shape: i32,
	pub dane_certificate_signature: bool,
	pub dane_hash_presence: bool,
	pub dane_hash: String,
	pub dane_public_key_signature: bool,
	pub dmarc_used: bool,
	pub dmarc_v: String,
	pub dmarc_adkim: String,
	pub dmarc_aspf: String,
	pub dmarc_fo: String,
	pub dmarc_p: String,
	pub dmarc_pct: i32,
	pub dmarc_sp: String,
	pub dmarc_rf: String,
	pub dmarc_ri: String,
	pub dmarc_rua: String,
	pub dmarc_ruf: String,
	pub mta_used: bool,
	pub mta_version: String,
	pub mta_sn: String,
	pub spf_used: bool,
	pub spf_version: String,
	pub spf_mechanisms: Vec<String>,
	pub spf_qualifier: String,
	pub spf_ip: Vec<String>,
	pub spf_include: Vec<String>,
	pub spf_all: String,
	pub tls_rpt_used: bool,
	pub tls_rpt_v: String,
	pub tls_rpt_rua: String,
}

/// # Brief
/// Brand Indicators for Message Identification - Learn more about [bimi](https://www.validity.com/email-authentication/bimi/) 
/// # Attributes
/// - `used` *bool* : Whether the bimi record is used
/// - `version` *String* : current version of bimi protocol
/// - `url_sender` *String* : The URL where the sender's logo (image) is hosted
/// - `url_policy` *String* : URL where the sender's bimi policy is published
/// - `url_reputation` *String* : URL linked to a reputation service providing information about the sender's reliability and legitimacy
/// - `hash` *String* : Hash of the sender's image
/// - `s` *String* : Signature of the sender's image
#[derive(Serialize, Debug)]
pub struct BIMI
{
	pub used: bool,
	pub version: String,
	pub url_sender: String,
	pub url_policy: String,
	pub url_reputation: String,
	pub hash: String,
	pub s: String,
}

/// # Brief
/// Certificate record
/// # Attributes
/// - `used` *bool* : Whether the certificate record is used
/// - `signature_algorithm_server` *String* : signature algorithmique utilisé par le serveur
/// - `issuer_server` *IssuerDetails* : données de l'expéditeur du serveur
/// - `validity_server` *ValidityDetails* : structure contenant les details sur la validité du serveur
/// - `subject_server` *SubjectDetails* : structure contenant les details sur le sujet du serveur
/// - `extensions_server_subject_alternative_names` *Vec<String>* : structure contenant les details sur les extensions du serveur   dezfjerifezfjzeofjo Alternative names of the subject
/// - `signature_algorithm_intermediate` *String*: signature algorithmique utilisé par le serveur intermédiaire
/// - `issuer_intermediate` *IssuerDetails*: : données de l'expéditeur du serveur intermédiaire
/// - `validity_intermediate` *ValidityDetails* : structure contenant les details sur la validité du serveur intermédiaire
/// - `subject_intermediate` *SubjectDetails* : structure contenant les details sur le sujet du serveur intermédiaire
/// - `extensions_intermediate_subject_alternative_names` *Vec<String>* : structure contenant les details sur les extensions du serveur intermédiaire    dezfjerifezfjzeofjo Alternative names of the subject
#[derive(Serialize, Debug)]
pub struct Certificate
{
	pub used: bool,
	pub signature_algorithm_server: String,
	pub issuer_server: IssuerDetails,
	pub validity_server: ValidityDetails,
	pub subject_server: SubjectDetails,
	pub extensions_server_subject_alternative_names: Vec<String>,
	pub signature_algorithm_intermediate: String,
	pub issuer_intermediate: IssuerDetails,
	pub validity_intermediate: ValidityDetails,
	pub subject_intermediate: SubjectDetails,
	pub extensions_intermediate_subject_alternative_names: Vec<String>,
}

/// # Brief
/// Structure containing the issuer data
/// # Attributes
/// - `city` *String* : City
/// - `state` *String* : State
/// - `locality` *String* : Locality
/// - `common_name` *String* : Common name
#[derive(Serialize, Debug)]
pub struct IssuerDetails
{
	pub city: String,
	pub state: String,
	pub locality: String,
	pub organization: String,
	pub common_name: String,
}

/// # Brief
/// Structure containing the subject data
/// # Attributes
/// - `city` *String* : City
/// - `state` *String* : State
/// - `locality` *String* : Locality
/// - `common_name` *String* : Common name
#[derive(Serialize, Debug)]
pub struct SubjectDetails
{
	pub city: String,
	pub state: String,
	pub locality: String,
	pub organization: String,
	pub common_name: String,
}

/// # Brief
/// Structure contenant les données de validité
/// # Attributes
/// - `not_before` *String* : Début de validité du certificat
/// - `not_after` *String* : Fin de validité du certificat
/// - `is_valid` *bool* : Validité du certificat
#[derive(Serialize, Debug)]
pub struct ValidityDetails
{
	pub not_before: String,
	pub not_after: String,
	pub is_valid: bool,
}

/// # Brief
/// DNS-based Authentication of Named Entities - Learn more about [dane](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities)
/// # Attributes
/// - `used` *bool* : Whether the dane record is used
/// - `certificate_shape` *i32* : Shape of the certificate
/// - `certificate_signature` *bool* : Whether the certificate is signed
/// - `hash_presence` *bool* : Whether a hash is present
/// - `hash` *String* : The hash of the certificate
/// - `public_key_signature` *bool* : Whether the public key is signed
#[derive(Serialize, Debug)]
pub struct DANE
{
	pub used: bool,
	pub certificate_shape: i32,
	pub certificate_signature: bool,
	pub hash_presence: bool,
	pub hash: String,
	pub public_key_signature: bool,
}

/// # Brief
/// Domain-based Message Authentication, Reporting and Conformance - Learn more about [dmarc](https://www.validity.com/blog/demystifying-the-dmarc-record/)
/// # Attributes
/// - `used` *bool* : Whether the dmarc record is used
/// - `v` *String* : Version of dmarc protocol
/// - `adkim` *String* : Alignment mode for dkmin
/// - `aspf` *String* : Alignment mode for spf
/// - `fo` *String* : Reporting fails of options
/// - `p` *String* : Requested policy
/// - `pct` *i16* : Percentage of messages subjected  to applying the dmarc policy
/// - `sp` *String* : Requested policy for subdomains
/// - `rf` *String* : Format to use for reports of specific legal informations about the message  
/// - `ri` *String* : Interval in seconds between aggregate reports
/// - `rua` *String* : URL to which aggregate reports are sent
/// - `ruf` *String* : URL to which reports of failures are sent
/// # Warning
/// Uncompleted structure
#[derive(Serialize, Debug)]
pub struct DMARC
{
	pub used: bool,
	pub v: String,
	pub adkim: String,
	pub aspf: String,
	pub fo: String,
	pub p: String,
	pub pct: i32,
	pub sp: String,
	pub rf: String,
	pub ri: String,
	pub rua: String,
	pub ruf: String,
}

/// # Brief
/// Mail Transfer Agent Strict Transport Security - Learn more about [mta-sts](https://powerdmarc.com/what-is-mta-sts-and-why-do-you-need-it/)
/// # Attributes
/// - `used` *bool* : Whether the mta-sts record is used
/// - `version` *String* : version of mta-sts
/// - `sn` *String* : serial number
/// # Warning
/// version doit être un *i32* et pas un *String*.
#[derive(Serialize, Debug)]
pub struct MTASTS
{
	pub used: bool,
	pub version: String,
	pub sn: String,
}

/// # Brief
/// Sender Policy Framework - Learn more about [spf](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
/// # Attributes
/// - `used` *bool* : Whether the spf record is used
/// - version *String* : Version of spf
/// - mechanisms *Vec<String>* : List of mechanisms of verification
/// - ip *Vec<String>* : List of allowed IPv4 addresses
/// - include *Vec<String>* : list of included domains
/// - redirect *String* : To redirect the evaluation of the SPF policy to another domain
/// - all *String* : Verification mechanism that specifies what action to take if none of the previous checks match
// #[derive(Serialize, Debug)]
#[derive(Queryable, Deserialize, Serialize)]
#[diesel(sql_type = Jsonb)]
pub struct SPF
{
	pub used: bool,
	pub version: String,
	pub mechanisms: Vec<String>,
	pub qualifier: String,
	pub ip: Vec<String>,
	pub include: Vec<String>,
	pub all: String,
}

/// # Brief
/// Transport Layer Security Real-Time Transport Protocol- Learn more about [tls-rpt](https://en.wikipedia.org/wiki/Secure_Real-time_Transport_Protocol)
/// # Attributes
/// - `used` *bool* : Whether the tls record is used
/// - `v` *String* : Version of tls-rpt
/// - `rua` *String* : URL to which reports are sent
#[derive(Serialize, Debug)]
pub struct TLSRTP
{
	pub used: bool,
	pub v: String,
	pub rua: String,
}
