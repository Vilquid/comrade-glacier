pub mod logger;
pub mod schema;
pub mod bdd;
pub mod models;
mod domain;
mod get_cert;


use logger::log;


fn main()
{
	log("INFO", "Début du programme Comrade Glacier");
	println!("Hi comrade glacier");
}
