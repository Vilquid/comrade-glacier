pub mod logger;
pub mod schema;
pub mod bdd;
pub mod model;
mod domain;
mod get_cert;


use logger::log;


fn main()
{
	log("INFO", "Début du programme Comrade Glacier");
	println!("Hi comrade glacier");
}
