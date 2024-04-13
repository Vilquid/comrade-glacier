pub mod logger;
pub mod schema;
pub mod bdd;
pub mod models;
mod domain;
mod get_cert;
mod ip;


use logger::log;
// use crate::bdd::add_domain;


fn main()
{
	log("INFO", "Start of Comrade Glacier");
	println!("Hi comrade glacier");
}
