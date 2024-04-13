use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use regex::Regex;
use dns_lookup::lookup_addr;
use dotenv::dotenv;
use crate::domain::dns;
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
	if !Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$").unwrap().is_match(&ip)
	{
		log("ERROR", format!("The IP {} is not valid", ip).as_str());
		return;
	}

	let port: String = "25".to_string();
	let socket: String = format!("{}:{}", ip, port);
	let socket = socket.parse::<SocketAddr>().unwrap();

	// if the port 25 is not open
	if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_err()
	{
		return;
	}

	let ip: std::net::IpAddr = ip.parse().unwrap();
	let host = lookup_addr(&ip).unwrap();
	let host = host.to_string();

	dns(host.as_str());
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
pub(crate) fn last_scanned_ip() -> String
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
pub fn save_last_scanned_ip(ip: String)
{
	dotenv().ok();
	std::env::set_var("LAST_SCANNED_IP", ip);
}
