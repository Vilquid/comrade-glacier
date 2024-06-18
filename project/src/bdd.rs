use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use crate::domain::dns;
use crate::models::{Domain, NewPort, Port};
use crate::schema::{domains, ports};


/// # Brief
/// Establish a connection to the database
/// # Attributes
/// inline
/// # Parameters
/// **Nothing**
/// # Return
/// *PgConnection* - Connection to the database
/// # Usage
/// mod bdd;
/// pub fn add_domain(domain: &str) -> Domain
/// {
///     let mut connection = establish_connection();
/// 
///     diesel::insert_into(domains::table)
///         .values(&dns(domain))
///         .returning(Domain::as_returning())
///         .get_result(&mut connection)
///         .expect("Error saving new domain")
/// }
#[inline]
fn establish_connection() -> PgConnection
{
	dotenv().ok();
	
	let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	PgConnection::establish(&database_url)
		.unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

/// # Brief
/// Add a port to the table `ports`
/// # Attributes
/// inline
/// # Parameters
/// - `port` *NewPort* - Port to add to the table `ports`
/// # Return
/// *Port* - The port added to the table `ports`
/// # Comments
/// La fonction peut buguer
#[inline]
pub fn add_port(port: NewPort) -> Port
{
	let mut connection = establish_connection();

	diesel::insert_into(ports::table)
		.values(&port)
		.returning(Port::as_returning())
		.get_result(&mut connection)
		.expect("Error saving new port")
}

/// # Brief
/// Add a domain to the table `domains`
/// # Attributes
/// inline
/// # Parameters
/// - `domain` *&str* - Domain to add to the table `domains`
/// # Return
/// *Domain* - The domain added to the table `domains`
/// # Usage
/// mod logger;
/// use crate::bdd::add_domain;
/// fn main()
/// {
///     add_domain("gmail.com");
/// }
/// # Comments
/// La fonction peut buguer
#[inline]
pub fn add_domain(domain: &str) -> Domain
{
	let mut connection = establish_connection();

	diesel::insert_into(domains::table)
		.values(&dns(domain))
		.returning(Domain::as_returning())
		.get_result(&mut connection)
		.expect("Error saving new domain")
}