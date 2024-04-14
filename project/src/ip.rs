use std::{fs, io};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use regex::Regex;
use dns_lookup::lookup_addr;
use dotenv::dotenv;
use std::io::Write;
use crate::bdd::add_domain;
use crate::logger::log;


/// # Brief
/// Check if the IP is valid and if the port 25 is open
/// # Attributes
/// inline
/// # Parameters
/// - `ip` *String* - IP to check
/// # Return
/// **Nothing**
/// # Usage
/// mod ip;
/// ip("8.8.8.8".to_string());
#[inline]
pub(crate) fn ip(ip: String)
{
	println!("ip: {}", ip);
	// Verify if the IP is valid
	if !Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$").unwrap().is_match(&ip)
	{
		log("ERROR", format!("The IP {} is not valid", ip).as_str());
		return;
	}

	let socket = format!("{}:{}", ip, "25").parse::<SocketAddr>().unwrap();

	// if the port 25 is not open
	if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_err()
	{
		return;
	}

	// if the port 25 is open
	let ip: std::net::IpAddr = ip.parse().unwrap();
	let host = lookup_addr(&ip).unwrap();
	let host = host.to_string();

	println!("{}:{}", ip, host);
	add_domain(&host);
}

/// # Brief
/// Get the last scanned IP
/// # Attributes
/// inline
/// # Return
/// **String**
/// # Usage
/// mod ip;
/// let last_ip = last_scanned_ip();
#[inline]
pub fn last_scanned_ip() -> String
{
	dotenv().ok();
	std::env::var("LAST_SCANNED_IP").unwrap().to_string()
}

/// # Brief
/// Save the last scanned IP in the environment variables
/// # Attributes
/// inline
/// # Parameters
/// - `ip` *String* - IP to save
/// # Return
/// **Nothing**
/// # Usage
/// mod ip;
/// save_last_scanned_ip("1.1.1.1".to_string());
#[inline]
pub fn save_last_scanned_ip(ip: String) -> io::Result<()>
{
	let dotenv_path = ".env";
	let temp_path = ".env.tmp";

	// Tenter d'ouvrir le fichier .env, gérer l'erreur s'il n'existe pas
	let input = match fs::File::open(dotenv_path)
	{
		Ok(file) => file,
		Err(e) => {
			eprintln!("Erreur lors de l'ouverture de {}: {}", dotenv_path, e);
			return Err(e);
		}
	};
	let buffered = BufReader::new(input);

	let mut output = match OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.open(temp_path)
	{
		Ok(file) => file,
		Err(e) => {
			return Err(e);
		}
	};

	for line in buffered.lines()
	{
		let line = match line {
			Ok(ln) => ln,
			Err(e) => {
				return Err(e);
			}
		};
		
		if line.starts_with("LAST_SCANNED_IP=")
		{
			if let Err(e) = writeln!(output, "LAST_SCANNED_IP={}", ip)
			{
				return Err(e);
			}
		} else if let Err(e) = writeln!(output, "{}", line) {
  			return Err(e);
		}
	}

	// Renommer le fichier temporaire pour remplacer l'ancien .env
	fs::rename(temp_path, dotenv_path)?;

	Ok(())
}
