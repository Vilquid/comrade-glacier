use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use crate::models::{Domain, NewDomain, NewPort, Port};
use crate::schema::{domains, ports};

pub fn establish_connection() -> PgConnection
{
	dotenv().ok();

	let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	PgConnection::establish(&database_url)
		.unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn add_port(conn: &mut PgConnection, data: Port) -> Port
{
	let port = NewPort
	{
		ip: data.ip,
		port_25_open: data.port_25_open,
		domain: data.domain,
	};

	diesel::insert_into(ports::table)
		.values(&port)
		.returning(Port::as_returning())
		.get_result(conn)
		.expect("Error saving new port")
}

pub fn add_domain(conn: &mut PgConnection, data: Domain) -> Domain
{
	// let spf_json = serde_json::to_value(data.spf).expect("Error converting spf to json");

	let domain = NewDomain
	{
		domain: data.domain,
		bimi: data.bimi,
		certificate: data.certificate,
		dane: data.dane,
		dmarc: data.dmarc,
		mta: data.mta,
		tls_rpt: data.tls_rpt,
		spf: data.spf
	};

	diesel::insert_into(domains::table)
		.values(&domain)
		.returning(Domain::as_returning())
		.get_result(conn)
		.expect("Error saving new port")
}