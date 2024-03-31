use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use crate::model::Port;
use crate::schema::ports;

pub fn establish_connection() -> PgConnection
{
	dotenv().ok();

	let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	PgConnection::establish(&database_url)
		.unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn add_port(conn: &mut PgConnection, data: Port) -> Port
{
	let port = Port
	{
		id: 0,
		ip: data.ip,
		port_25_open: data.port_25_open,
		domain: data.domain,
	}:

	diesel::insert_into(ports::table)
		.values(&port)
		.returning(Port::as_returning())
		.get_result(conn)
		.expect("Error saving new post")
}

