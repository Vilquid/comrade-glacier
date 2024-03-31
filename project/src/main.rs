pub mod logger;
pub mod schema;
pub mod bdd;
pub mod models;
mod domain;
mod get_cert;


use logger::log;
use crate::bdd::add_domain;
use crate::domain::dns;


fn main()
{
	log("INFO", "Début du programme Comrade Glacier");
	println!("Hi comrade glacier");
	
	let domain = "gmail.com";
	add_domain(&mut bdd::establish_connection(), dns(domain));
}
