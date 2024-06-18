// use der_parser::der::Tag;
// use der_parser::oid::Oid;
// use nom::HexDisplay;
// use std::borrow::Borrow;
// use std::cmp::min;
// use std::convert::TryFrom;
// use std::fs::File;
// use std::io;
// use std::io::{Read, Write};
// use std::net::{Ipv4Addr, Ipv6Addr};
// use x509_parser::prelude::*;
// use x509_parser::public_key::PublicKey;
// use x509_parser::signature_algorithm::SignatureAlgorithm;
// use std::process::{Command, Stdio};
// use regex::Regex;
// use chrono::{Utc, TimeZone, DateTime};
// 
// 
// #[derive(Debug, PartialEq)]
// pub struct ServerCert {
// 	pub subject_country: String,
// 	pub subject_state: String,
// 	pub subject_locality: String,
// 	pub subject_organization: String,
// 	pub subject_common_name: String,
// 	pub issuer_country: String,
// 	pub issuer_state: String,
// 	pub issuer_locality: String,
// 	pub issuer_organization: String,
// 	pub issuer_common_name: String,
// 	pub not_before: DateTime<Utc>,
// 	pub not_after: DateTime<Utc>,
// 	pub is_valid: bool,
// 	pub pki_algorithm_oid: String,
// 	pub pki_algorithm_bytes: String,
// 	pub pki_algorithm_exponent: String,
// 	pub signature_algorithm: String,
// 	pub signature_value: String,
// 	pub extensions_authority_key_identifier: String,
// 	pub extensions_authority_key_cert_issuer: String,
// 	pub extensions_authority_key_cert_serial: String,
// 	pub extensions_basic_constraints: String,
// 	pub extensions_crl_full_name: String,
// 	pub extensions_crl_reasons: String,
// 	pub extensions_crl_issuer: String,
// 	pub extensions_key_usage: String,
// 	pub extensions_subject_key_identifier: String,
// 	pub extensions_subject_alternate_names: String,
// }
// 
// #[derive(Debug, PartialEq)]
// pub struct IntermediateCert {
// 	pub subject_country: String,
// 	pub subject_state: String,
// 	pub subject_locality: String,
// 	pub subject_organization: String,
// 	pub subject_common_name: String,
// 	pub issuer_country: String,
// 	pub issuer_state: String,
// 	pub issuer_locality: String,
// 	pub issuer_organization: String,
// 	pub issuer_common_name: String,
// 	pub not_before: DateTime<Utc>,
// 	pub not_after: DateTime<Utc>,
// 	pub is_valid: bool,
// 	pub pki_algorithm_oid: String,
// 	pub pki_algorithm_bytes: String,
// 	pub pki_algorithm_exponent: String,
// 	pub signature_algorithm: String,
// 	pub signature_value: String,
// 	pub extensions_authority_key_identifier: String,
// 	pub extensions_authority_key_cert_issuer: String,
// 	pub extensions_authority_key_cert_serial: String,
// 	pub extensions_basic_constraints: String,
// 	pub extensions_crl_full_name: String,
// 	pub extensions_crl_reasons: String,
// 	pub extensions_crl_issuer: String,
// 	pub extensions_key_usage: String,
// 	pub extensions_subject_key_identifier: String,
// 	pub extensions_subject_alternate_names: String,
// }
// 
// #[derive(Debug, PartialEq)]
// pub struct Cert {
// 	pub server: ServerCert,
// 	pub intermediate: IntermediateCert,
// }
// 
// #[allow(unused)]
// fn print_hex_dump(bytes: &[u8], max_len: usize) {
// 	let m = min(bytes.len(), max_len);
// 	print!("{}", &bytes[..m].to_hex(16));
// 	if bytes.len() > max_len {
// 		println!("... <continued>");
// 	}
// }
// 
// #[allow(unused)]
// 
// fn format_oid(oid: &Oid) -> String {
// 	match oid2sn(oid, oid_registry()) {
// 		Ok(s) => s.to_owned(),
// 		_ => format!("{}", oid),
// 	}
// }
// 
// #[allow(unused)]
// 
// fn generalname_to_string(gn: &GeneralName) -> String {
// 	match gn {
// 		GeneralName::DNSName(name) => format!("DNSName:{}", name),
// 		GeneralName::DirectoryName(n) => format!("DirName:{}", n),
// 		GeneralName::EDIPartyName(obj) => format!("EDIPartyName:{:?}", obj),
// 		GeneralName::IPAddress(n) => format!("IPAddress:{:?}", n),
// 		GeneralName::OtherName(oid, n) => format!("OtherName:{}, {:?}", oid, n),
// 		GeneralName::RFC822Name(n) => format!("RFC822Name:{}", n),
// 		GeneralName::RegisteredID(oid) => format!("RegisteredID:{}", oid),
// 		GeneralName::URI(n) => format!("URI:{}", n),
// 		GeneralName::X400Address(obj) => format!("X400Address:{:?}", obj),
// 	}
// }
// 
// fn print_x509_extension(oid: &Oid, ext: &X509Extension) {
// 	println!(
// 		"    [crit:{} l:{}] {}: ",
// 		ext.critical,
// 		ext.value.len(),
// 		format_oid(oid)
// 	);
// 	match ext.parsed_extension() {
// 		ParsedExtension::AuthorityKeyIdentifier(aki) => {
// 			println!("      X509v3 Authority Key Identifier");
// 			if let Some(key_id) = &aki.key_identifier {
// 				println!("        Key Identifier: {:x}", key_id);
// 			}
// 			if let Some(issuer) = &aki.authority_cert_issuer {
// 				for name in issuer {
// 					println!("        Cert Issuer: {}", name);
// 				}
// 			}
// 			if let Some(serial) = aki.authority_cert_serial {
// 				println!("        Cert Serial: {}", format_serial(serial));
// 			}
// 		}
// 		ParsedExtension::BasicConstraints(bc) => {
// 			println!("      X509v3 CA: {}", bc.ca);
// 		}
// 		ParsedExtension::CRLDistributionPoints(points) => {
// 			println!("      X509v3 CRL Distribution Points:");
// 			for point in points.iter() {
// 				if let Some(name) = &point.distribution_point {
// 					println!("        Full Name: {:?}", name);
// 				}
// 				if let Some(reasons) = &point.reasons {
// 					println!("        Reasons: {}", reasons);
// 				}
// 				if let Some(crl_issuer) = &point.crl_issuer {
// 					print!("        CRL Issuer: ");
// 					for gn in crl_issuer {
// 						print!("{} ", generalname_to_string(gn));
// 					}
// 					println!();
// 				}
// 				println!();
// 			}
// 		}
// 		ParsedExtension::KeyUsage(ku) => {
// 			println!("      X509v3 Key Usage: {}", ku);
// 		}
// 		ParsedExtension::NSCertType(ty) => {
// 			println!("      Netscape Cert Type: {}", ty);
// 		}
// 		ParsedExtension::SubjectAlternativeName(san) => {
// 			for name in &san.general_names {
// 				let s = match name {
// 					GeneralName::DNSName(s) => {
// 						format!("DNS:{}", s)
// 					}
// 					GeneralName::IPAddress(b) => {
// 						let ip = match b.len() {
// 							4 => {
// 								let b = <[u8; 4]>::try_from(*b).unwrap();
// 								let ip = Ipv4Addr::from(b);
// 								format!("{}", ip)
// 							}
// 							16 => {
// 								let b = <[u8; 16]>::try_from(*b).unwrap();
// 								let ip = Ipv6Addr::from(b);
// 								format!("{}", ip)
// 							}
// 							l => format!("invalid (len={})", l),
// 						};
// 						format!("IP Address:{}", ip)
// 					}
// 					_ => {
// 						format!("{:?}", name)
// 					}
// 				};
// 				println!("      X509v3 SAN: {}", s);
// 			}
// 		}
// 		ParsedExtension::SubjectKeyIdentifier(id) => {
// 			println!("      X509v3 Subject Key Identifier: {:x}", id);
// 		}
// 		x => println!("      {:?}", x),
// 	}
// }
// 
// fn print_x509_digest_algorithm(alg: &AlgorithmIdentifier, level: usize) {
// 	println!(
// 		"{:indent$}Oid: {}",
// 		"",
// 		format_oid(&alg.algorithm),
// 		indent = level
// 	);
// 	if let Some(parameter) = &alg.parameters {
// 		let s = match parameter.tag() {
// 			Tag::Oid => {
// 				let oid = parameter.as_oid().unwrap();
// 				format_oid(&oid)
// 			}
// 			_ => format!("{}", parameter.tag()),
// 		};
// 		println!("{:indent$}Parameter: <PRESENT> {}", "", s, indent = level);
// 		let bytes = parameter.as_bytes();
// 		print_hex_dump(bytes, 32);
// 	} else {
// 		println!("{:indent$}Parameter: <ABSENT>", "", indent = level);
// 	}
// }
// 
// #[allow(unused)]
// 
// fn print_x509_info(x509: &X509Certificate) -> io::Result<()> {
// 	let version = x509.version();
// 	if version.0 < 3 {
// 		println!("  Version: {}", version);
// 	} else {
// 		println!("  Version: INVALID({})", version.0);
// 	}
// 	println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
// 
// 	println!("  Subject: {}", x509.subject());
// 
// 	println!(" Issuer: {}", x509.issuer());
// 
// 	println!("  Validity:");
// 	println!("    NotBefore: {}", x509.validity().not_before);
// 	println!("    NotAfter:  {}", x509.validity().not_after);
// 	println!("    is_valid:  {}", x509.validity().is_valid());
// 
// 	println!("  Subject Public Key Info:");
// 	print_x509_ski(x509.public_key());
// 
// 
// 	print_x509_signature_algorithm(&x509.signature_algorithm, 4);
// 
// 	//let signature = &x509.signature_algorithm;
// 
// 
// 	println!("  Signature Algorithm: ");
// 	println!("  Signature Value:");
// 	for l in format_number_to_hex_with_colon(&x509.signature_value.data, 16) {
// 		println!("      {}", l);
// 	}
// 
// 
// 	println!("  Extensions:");
// 	for ext in x509.extensions() {
// 		print_x509_extension(&ext.oid, ext);
// 	}
// 
// 
// 	println!();
// 
// 
// 	print!("Structure validation status: ");
// 	#[cfg(feature = "validate")]
// 	{
// 		let mut logger = VecLogger::default();
// 		// structure validation status
// 		let ok = X509StructureValidator
// 			.chain(X509CertificateValidator)
// 			.validate(x509, &mut logger);
// 		if ok {
// 			println!("Ok");
// 		} else {
// 			println!("FAIL");
// 		}
// 		for warning in logger.warnings() {
// 			println!("  [W] {}", warning);
// 		}
// 		for error in logger.errors() {
// 			println!("  [E] {}", error);
// 		}
// 		println!();
// 		if VALIDATE_ERRORS_FATAL && !logger.errors().is_empty() {
// 			return Err(io::Error::new(io::ErrorKind::Other, "validation failed"));
// 		}
// 	}
// 	#[cfg(not(feature = "validate"))]
// 	{
// 		println!("Unknown (feature 'validate' not enabled)");
// 	}
// 	#[cfg(feature = "verify")]
// 	{
// 		print!("Signature verification: ");
// 		if x509.subject() == x509.issuer() {
// 			if x509.verify_signature(None).is_ok() {
// 				println!("OK");
// 				println!("  [I] certificate is self-signed");
// 			} else if x509.subject() == x509.issuer() {
// 				println!("FAIL");
// 				println!("  [W] certificate looks self-signed, but signature verification failed");
// 			}
// 		} else {
// 			// if subject is different from issuer, we cannot verify certificate without the public key of the issuer
// 			println!("N/A");
// 		}
// 	}
// 
// 	Ok(())
// }
// 
// fn print_x509_signature_algorithm(signature_algorithm: &AlgorithmIdentifier, indent: usize) {
// 	match SignatureAlgorithm::try_from(signature_algorithm) {
// 		Ok(sig_alg) => {
// 			print!("  Signature Algorithm: ");
// 			match sig_alg {
// 				SignatureAlgorithm::DSA => println!("DSA"),
// 				SignatureAlgorithm::ECDSA => println!("ECDSA"),
// 				SignatureAlgorithm::ED25519 => println!("ED25519"),
// 				SignatureAlgorithm::RSA => println!("RSA"),
// 				SignatureAlgorithm::RSASSA_PSS(params) => {
// 					println!("RSASSA-PSS");
// 					let indent_s = format!("{:indent$}", "", indent = indent + 2);
// 					println!(
// 						"{}Hash Algorithm: {}",
// 						indent_s,
// 						format_oid(params.hash_algorithm_oid()),
// 					);
// 					print!("{}Mask Generation Function: ", indent_s);
// 					if let Ok(mask_gen) = params.mask_gen_algorithm() {
// 						println!(
// 							"{}/{}",
// 							format_oid(&mask_gen.mgf),
// 							format_oid(&mask_gen.hash),
// 						);
// 					} else {
// 						println!("INVALID");
// 					}
// 					println!("{}Salt Length: {}", indent_s, params.salt_length());
// 				}
// 				SignatureAlgorithm::RSAAES_OAEP(params) => {
// 					println!("RSAAES-OAEP");
// 					let indent_s = format!("{:indent$}", "", indent = indent + 2);
// 					println!(
// 						"{}Hash Algorithm: {}",
// 						indent_s,
// 						format_oid(params.hash_algorithm_oid()),
// 					);
// 					print!("{}Mask Generation Function: ", indent_s);
// 					if let Ok(mask_gen) = params.mask_gen_algorithm() {
// 						println!(
// 							"{}/{}",
// 							format_oid(&mask_gen.mgf),
// 							format_oid(&mask_gen.hash),
// 						);
// 					} else {
// 						println!("INVALID");
// 					}
// 					println!(
// 						"{}pSourceFunc: {}",
// 						indent_s,
// 						format_oid(&params.p_source_alg().algorithm),
// 					);
// 				}
// 			}
// 		}
// 		Err(e) => {
// 			eprintln!("Could not parse signature algorithm: {}", e);
// 			println!("  Signature Algorithm:");
// 			print_x509_digest_algorithm(signature_algorithm, indent);
// 		}
// 	}
// }
// 
// fn print_x509_ski(public_key: &SubjectPublicKeyInfo) {
// 	println!("    Public Key Algorithm:");
// 	print_x509_digest_algorithm(&public_key.algorithm, 6);
// 	match public_key.parsed() {
// 		Ok(PublicKey::RSA(rsa)) => {
// 			println!("    RSA Public Key: ({} bit)", rsa.key_size());
// 			// print_hex_dump(rsa.modulus, 1024);
// 			for l in format_number_to_hex_with_colon(rsa.modulus, 16) {
// 				println!("        {}", l);
// 			}
// 			if let Ok(e) = rsa.try_exponent() {
// 				println!("    exponent: 0x{:x} ({})", e, e);
// 			} else {
// 				println!("    exponent: <INVALID>:");
// 				print_hex_dump(rsa.exponent, 32);
// 			}
// 		}
// 		Ok(PublicKey::EC(ec)) => {
// 			println!("    EC Public Key: ({} bit)", ec.key_size());
// 			for l in format_number_to_hex_with_colon(ec.data(), 16) {
// 				println!("        {}", l);
// 			}
// 			// // identify curve
// 			// if let Some(params) = &public_key.algorithm.parameters {
// 			//     let curve_oid = params.as_oid();
// 			//     let curve = curve_oid
// 			//         .map(|oid| {
// 			//             oid_registry()
// 			//                 .get(oid)
// 			//                 .map(|entry| entry.sn())
// 			//                 .unwrap_or("<UNKNOWN>")
// 			//         })
// 			//         .unwrap_or("<ERROR: NOT AN OID>");
// 			//     println!("    Curve: {}", curve);
// 			// }
// 		}
// 		Ok(PublicKey::DSA(y)) => {
// 			println!("    DSA Public Key: ({} bit)", 8 * y.len());
// 			for l in format_number_to_hex_with_colon(y, 16) {
// 				println!("        {}", l);
// 			}
// 		}
// 		Ok(PublicKey::GostR3410(y)) => {
// 			println!("    GOST R 34.10-94 Public Key: ({} bit)", 8 * y.len());
// 			for l in format_number_to_hex_with_colon(y, 16) {
// 				println!("        {}", l);
// 			}
// 		}
// 		Ok(PublicKey::GostR3410_2012(y)) => {
// 			println!("    GOST R 34.10-2012 Public Key: ({} bit)", 8 * y.len());
// 			for l in format_number_to_hex_with_colon(y, 16) {
// 				println!("        {}", l);
// 			}
// 		}
// 		Ok(PublicKey::Unknown(b)) => {
// 			println!("    Unknown key type");
// 			print_hex_dump(b, 256);
// 			if let Ok((rem, res)) = der_parser::parse_der(b) {
// 				eprintln!("rem: {} bytes", rem.len());
// 				eprintln!("{:?}", res);
// 			} else {
// 				eprintln!("      <Could not parse key as DER>");
// 			}
// 		}
// 		Err(_) => {
// 			println!("    INVALID PUBLIC KEY");
// 		}
// 	}
// 	// dbg!(&public_key);
// 	// todo!();
// }
// 
// fn format_number_to_hex_with_colon(b: &[u8], row_size: usize) -> Vec<String> {
// 	let mut v = Vec::with_capacity(1 + b.len() / row_size);
// 	for r in b.chunks(row_size) {
// 		let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
// 			a + &format!("{:02x}:", b)
// 		});
// 		v.push(s)
// 	}
// 	v
// }
// 
// fn handle_certificate(file_name: &str, data: &[u8]) -> io::Result<(Option<ServerCert>, Option<IntermediateCert>)> {
// 	let mut server_cert: Option<ServerCert> = None;
// 	let mut intermediate_cert: Option<IntermediateCert> = None;
// 
// 	match parse_x509_certificate(data) {
// 		Ok((_, x509)) => {
// 			//print_x509_info(&x509)?;
// 
// 			let subject_str = x509.subject().to_string();
// 
// 			let mut subject_country = String::new();
// 			let mut subject_state = String::new();
// 			let mut subject_locality = String::new();
// 			let mut subject_organization = String::new();
// 			let mut subject_common_name = String::new();
// 
// 			for item in subject_str.split(", ") {
// 				let parts: Vec<&str> = item.split('=').collect();
// 				if parts.len() == 2 {
// 					match parts[0] {
// 						"C" => subject_country = parts[1].to_string(),
// 						"ST" => subject_state = parts[1].to_string(),
// 						"L" => subject_locality = parts[1].to_string(),
// 						"O" => subject_organization = parts[1].to_string(),
// 						"CN" => subject_common_name = parts[1].to_string(),
// 						_ => {}
// 					}
// 				}
// 			}
// 
// 			let issuer_str = x509.issuer().to_string();
// 
// 			let mut issuer_country = String::new();
// 			let mut issuer_state = String::new();
// 			let mut issuer_locality = String::new();
// 			let mut issuer_organization = String::new();
// 			let mut issuer_common_name = String::new();
// 
// 			for item in issuer_str.split(", ") {
// 				let parts: Vec<&str> = item.split('=').collect();
// 				if parts.len() == 2 {
// 					match parts[0] {
// 						"C" => issuer_country = parts[1].to_string(),
// 						"ST" => issuer_state = parts[1].to_string(),
// 						"L" => issuer_locality = parts[1].to_string(),
// 						"O" => issuer_organization = parts[1].to_string(),
// 						"CN" => issuer_common_name = parts[1].to_string(),
// 						_ => {}
// 					}
// 				}
// 			}
// 
// 			// let not_before = Utc.timestamp(x509.validity().not_before.timestamp(), 0).to_string();
// 			let not_before = Utc.timestamp_opt(x509.validity().not_before.timestamp(), 0).unwrap().to_string();
// 			// let not_after = Utc.timestamp(x509.validity().not_after.timestamp(), 0).to_string();
// 			let not_after = Utc.timestamp_opt(x509.validity().not_after.timestamp(), 0).unwrap().to_string();
// 			let is_valid = x509.validity().is_valid();
// 
// 			let pki_parsed = x509.public_key().parsed();
// 			let pki_parsed_str = format!("{:?}", pki_parsed);
// 
// 			let mut pki_algorithm_oid: String = "".to_string();
// 
// 			if let Some(start_index) = pki_parsed_str.find("Ok(") {
// 				if let Some(end_index) = pki_parsed_str[start_index..].find('{') {
// 					let extracted_str = &pki_parsed_str[start_index + 3..start_index + end_index];
// 					pki_algorithm_oid = extracted_str.parse().unwrap();
// 				}
// 			}
// 
// 			let mut pki_algorithm_bytes: String = "".to_string();
// 
// 			if let Some(start_index) = pki_parsed_str.find("modulus") {
// 				if let Some(end_index) = pki_parsed_str[start_index..].find(']') {
// 					let extracted_str = &pki_parsed_str[start_index + 10..start_index + end_index];
// 					pki_algorithm_bytes = extracted_str.parse().unwrap();
// 				}
// 			}
// 
// 			let mut pki_algorithm_exponent: String = "".to_string();
// 
// 			if let Some(start_index) = pki_parsed_str.find("exponent: [") {
// 				if let Some(end_index) = pki_parsed_str[start_index..].find(']') {
// 					let extracted_str = &pki_parsed_str[start_index + 11..start_index + end_index];
// 					pki_algorithm_exponent = extracted_str.parse().unwrap();
// 				}
// 			}
// 
// 
// 			let mut authority_key_identifier_str = String::new();
// 			let mut authority_cert_issuer_str = String::new();
// 			let mut authority_cert_serial_str = String::new();
// 
// 			let mut basic_constraints_str = String::new();
// 
// 			let mut crl_full_name_str = String::new();
// 			let mut crl_issuer_str = String::new();
// 			let mut crl_reasons_str = String::new();
// 
// 			let mut key_usage_str = String::new();
// 
// 			let mut ski_value_str = String::new();
// 
// 			let mut subject_alternative_name_str = String::new();
// 
// 
// 			for ext in x509.extensions() {
// 				//print_x509_extension(&ext.oid, ext);
// 				match ext.parsed_extension() {
// 					ParsedExtension::AuthorityKeyIdentifier(aki) => {
// 						//println!("      X509v3 Authority Key Identifier");
// 						if let Some(key_id) = &aki.key_identifier {
// 							//println!("        Key Identifier: {:x}", key_id);
// 							authority_key_identifier_str = format!("{:?}", key_id);
// 						}
// 						if let Some(issuer) = &aki.authority_cert_issuer {
// 							for name in issuer {
// 								//println!("        Cert Issuer: {}", name);
// 								authority_cert_issuer_str = format!("{:?}", name);
// 							}
// 						}
// 						if let Some(serial) = aki.authority_cert_serial {
// 							//println!("        Cert Serial: {}", format_serial(serial));
// 							authority_cert_serial_str = format!("{:?}", serial);
// 						}
// 					}
// 
// 					ParsedExtension::BasicConstraints(bc) => {
// 						//println!("      X509v3 CA: {}", bc.ca);
// 						basic_constraints_str = format!("{:?}", bc.ca);
// 					}
// 
// 					ParsedExtension::CRLDistributionPoints(points) => {
// 						//println!("      X509v3 CRL Distribution Points:");
// 						for point in points.iter() {
// 							if let Some(name) = &point.distribution_point {
// 								//println!("        Full Name: {:?}", name);
// 								crl_full_name_str = format!("{:?}", name);
// 							}
// 							if let Some(reasons) = &point.reasons {
// 								//println!("        Reasons: {}", reasons);
// 								crl_reasons_str = format!("{:?}", reasons);
// 							}
// 							if let Some(crl_issuer) = &point.crl_issuer {
// 								//print!("        CRL Issuer: ");
// 								let mut values: Vec<String> = Vec::new();
// 
// 								for gn in crl_issuer {
// 									//print!("{} ", generalname_to_string(gn));
// 									let value = generalname_to_string(gn);
// 									values.push(value);
// 									//print!("{} ", value);
// 									crl_issuer_str = values.join(" ");
// 								}
// 								//println!();
// 							}
// 							//println!();
// 						}
// 					}
// 
// 					ParsedExtension::KeyUsage(ku) => {
// 						//println!("      X509v3 Key Usage: {}", ku);
// 						key_usage_str = format!("{:?}", ku);
// 					}
// 
// 
// 					/* ParsedExtension::NSCertType(ty) => {
// 					 println!("      Netscape Cert Type: {}", ty);
// 				 }
// 
// 				 */
// 
// 					ParsedExtension::SubjectAlternativeName(san) => {
// 						for name in &san.general_names {
// 							let s = match name {
// 								GeneralName::DNSName(s) => {
// 									format!("DNS:{}", s)
// 								}
// 								GeneralName::IPAddress(b) => {
// 									let ip = match b.len() {
// 										4 => {
// 											let b = <[u8; 4]>::try_from(*b).unwrap();
// 											let ip = Ipv4Addr::from(b);
// 											format!("{}", ip)
// 										}
// 										16 => {
// 											let b = <[u8; 16]>::try_from(*b).unwrap();
// 											let ip = Ipv6Addr::from(b);
// 											format!("{}", ip)
// 										}
// 										l => format!("invalid (len={})", l),
// 									};
// 									format!("IP Address:{}", ip)
// 								}
// 								_ => {
// 									format!("{:?}", name)
// 								}
// 							};
// 							//println!("      X509v3 SAN: {}", s);
// 							subject_alternative_name_str.push_str(&s);
// 							subject_alternative_name_str.push(' '); // Add space between each SAN
// 						}
// 					}
// 
// 					ParsedExtension::SubjectKeyIdentifier(id) => {
// 						//println!("      X509v3 Subject Key Identifier: {:x}", id);
// 						let ski_value = id;
// 						ski_value_str = format!("{:?}", ski_value);
// 					}
// 					_x => println!(),
// 				}
// 			}
// 
// 			let signature_algorithm = SignatureAlgorithm::try_from(x509.signature_algorithm.borrow());
// 			let signature_algorithm_str = format!("{:?}", signature_algorithm);
// 
// 			let signature_value = x509.signature_value.data;
// 			let signature_value_str = format!("{:?}", signature_value);
// 
// 			if file_name.contains("server")
// 			{
// 				// It's the server certificate
// 				server_cert = Some(ServerCert {
// 					subject_country,
// 					subject_state,
// 					subject_locality,
// 					subject_organization,
// 					subject_common_name,
// 					issuer_country,
// 					issuer_state,
// 					issuer_locality,
// 					issuer_organization,
// 					issuer_common_name,
// 					not_before: not_before.parse().unwrap(),
// 					not_after: not_after.parse().unwrap(),
// 					is_valid,
// 					pki_algorithm_oid,
// 					pki_algorithm_bytes,
// 					pki_algorithm_exponent,
// 					signature_algorithm: signature_algorithm_str,
// 					signature_value: signature_value_str,
// 					extensions_authority_key_identifier: authority_key_identifier_str,
// 					extensions_authority_key_cert_issuer: authority_cert_issuer_str,
// 					extensions_authority_key_cert_serial: authority_cert_serial_str,
// 					extensions_basic_constraints: basic_constraints_str,
// 					extensions_crl_full_name: crl_full_name_str,
// 					extensions_crl_reasons: crl_reasons_str,
// 					extensions_crl_issuer: crl_issuer_str,
// 					extensions_key_usage: key_usage_str,
// 					extensions_subject_key_identifier: ski_value_str,
// 					extensions_subject_alternate_names: subject_alternative_name_str,
// 				});
// 			} else {
// 				// It's an intermediate certificate
// 				intermediate_cert = Some(IntermediateCert {
// 					subject_country,
// 					subject_state,
// 					subject_locality,
// 					subject_organization,
// 					subject_common_name,
// 					issuer_country,
// 					issuer_state,
// 					issuer_locality,
// 					issuer_organization,
// 					issuer_common_name,
// 					not_before: not_before.parse().unwrap(),
// 					not_after: not_after.parse().unwrap(),
// 					is_valid,
// 					pki_algorithm_oid,
// 					pki_algorithm_bytes,
// 					pki_algorithm_exponent,
// 					signature_algorithm: signature_algorithm_str,
// 					signature_value: signature_value_str,
// 					extensions_authority_key_identifier: authority_key_identifier_str,
// 					extensions_authority_key_cert_issuer: authority_cert_issuer_str,
// 					extensions_authority_key_cert_serial: authority_cert_serial_str,
// 					extensions_basic_constraints: basic_constraints_str,
// 					extensions_crl_full_name: crl_full_name_str,
// 					extensions_crl_reasons: crl_reasons_str,
// 					extensions_crl_issuer: crl_issuer_str,
// 					extensions_key_usage: key_usage_str,
// 					extensions_subject_key_identifier: ski_value_str,
// 					extensions_subject_alternate_names: subject_alternative_name_str,
// 				});
// 			}
// 			Ok((server_cert, intermediate_cert))
// 		}
// 		Err(e) => {
// 			let s = format!("Error while parsing {}: {}", file_name, e);
// 			Err(io::Error::new(io::ErrorKind::Other, s))
// 		}
// 	}
// }
// 
// 
// fn download_certificates(domain: &str) -> Result<(), Box<dyn std::error::Error>> {
// 	let openssl_cmd = format!(
// 		r#"openssl s_client -connect {}:{} -servername {} -showcerts"#,
// 		domain, 443, domain
// 	);
// 
// 	let mut child = Command::new("sh")
// 		.arg("-c")
// 		.arg(&openssl_cmd)
// 		.stdin(Stdio::null())  // Redirect stdin to null
// 		.stdout(Stdio::piped())
// 		.stderr(Stdio::null())  // Redirect stderr to null
// 		.spawn()?;
// 
// 	let mut output = String::new();
// 	if let Some(mut stdout) = child.stdout.take() {
// 		stdout.read_to_string(&mut output)?;
// 	}
// 
// 	let re = Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")?;
// 	let certs: Vec<&str> = re.find_iter(&output).map(|m| m.as_str()).collect();
// 
// 	let server_cert_pem = format!("{}_server.pem", domain);
// 	let mut server_cert_file = File::create(server_cert_pem)?;
// 	// let mut server_cert_file = File::create(&server_cert_pem)?;
// 	// if let Some(server_cert) = certs.get(0)
// 
// 	if let Some(server_cert) = certs.first()
// 	{
// 		server_cert_file.write_all(server_cert.as_bytes())?;
// 	} else {
// 		return Err("Failed to retrieve server certificate".into());
// 	}
// 
// 	for (index, intermediate_cert) in certs.iter().enumerate().skip(1) {
// 		let intermediate_cert_pem = format!("{}_intermediate{}.pem", domain, index);
// 		let mut intermediate_cert_file = File::create(&intermediate_cert_pem)?;
// 
// 		intermediate_cert_file.write_all(intermediate_cert.as_bytes())?;
// 	}
// 
// 	Ok(())
// }
// 
// #[allow(unused)]
// pub struct PrintX509Cert();
// 
// impl  PrintX509Cert {
// 	#[allow(unused)]
// 	pub fn from_domain(domain: &str) -> Result<Cert, io::Error> {
// 		if let Err(err) = download_certificates(domain) {
// 			eprintln!("Error: {}", err);
// 		} else {
// 			println!("Certificate downloaded successfully.");
// 		}
// 
// 		//println!("Server Certificate :");
// 
// 		/*
// 
// 		// Define the variables before the blocks
// 		let mut server_cert: ServerCert = ServerCert {
// 			subject_country: "".to_string(),
// 			subject_state: "".to_string(),
// 			subject_locality: "".to_string(),
// 			subject_organization: "".to_string(),
// 			subject_common_name: "".to_string(),
// 			issuer_country: "".to_string(),
// 			issuer_state: "".to_string(),
// 			issuer_locality: "".to_string(),
// 			issuer_organization: "".to_string(),
// 			issuer_common_name: "".to_string(),
// 			not_before: Default::default(),
// 			not_after: Default::default(),
// 			is_valid: false,
// 			pki_algorithm_oid: "".to_string(),
// 			pki_algorithm_bytes: "".to_string(),
// 			pki_algorithm_exponent: "".to_string(),
// 			signature_algorithm: "".to_string(),
// 			signature_value: "".to_string(),
// 			extensions_authority_key_identifier: "".to_string(),
// 			extensions_authority_key_cert_issuer: "".to_string(),
// 			extensions_authority_key_cert_serial: "".to_string(),
// 			extensions_basic_constraints: "".to_string(),
// 			extensions_crl_full_name: "".to_string(),
// 			extensions_crl_reasons: "".to_string(),
// 			extensions_crl_issuer: "".to_string(),
// 			extensions_key_usage: "".to_string(),
// 			extensions_subject_key_identifier: "".to_string(),
// 			extensions_subject_alternate_names: "".to_string(),
// 		};
// 		let mut intermediate_cert: IntermediateCert = IntermediateCert {
// 			subject_country: "".to_string(),
// 			subject_state: "".to_string(),
// 			subject_locality: "".to_string(),
// 			subject_organization: "".to_string(),
// 			subject_common_name: "".to_string(),
// 			issuer_country: "".to_string(),
// 			issuer_state: "".to_string(),
// 			issuer_locality: "".to_string(),
// 			issuer_organization: "".to_string(),
// 			issuer_common_name: "".to_string(),
// 			not_before: Default::default(),
// 			not_after: Default::default(),
// 			is_valid: false,
// 			pki_algorithm_oid: "".to_string(),
// 			pki_algorithm_bytes: "".to_string(),
// 			pki_algorithm_exponent: "".to_string(),
// 			signature_algorithm: "".to_string(),
// 			signature_value: "".to_string(),
// 			extensions_authority_key_identifier: "".to_string(),
// 			extensions_authority_key_cert_issuer: "".to_string(),
// 			extensions_authority_key_cert_serial: "".to_string(),
// 			extensions_basic_constraints: "".to_string(),
// 			extensions_crl_full_name: "".to_string(),
// 			extensions_crl_reasons: "".to_string(),
// 			extensions_crl_issuer: "".to_string(),
// 			extensions_key_usage: "".to_string(),
// 			extensions_subject_key_identifier: "".to_string(),
// 			extensions_subject_alternate_names: "".to_string(),
// 		};
// 
// 		 */
// 
// 		let mut server_cert: Option<ServerCert> = None; // Initialize as None
// 
// 
// 		let server_cert_file_name: String = format!("{}_server.pem", domain).parse().unwrap();
// 		let data_server_cert_file_name = std::fs::read(server_cert_file_name.clone()).expect("Unable to read file");
// 		for (n, pem) in Pem::iter_from_buffer(&data_server_cert_file_name).enumerate() {
// 			match pem {
// 				Ok(pem) => {
// 					let data_server_cert_file_name = &pem.contents;
// 					//println!("Certificate [{}]", n);
// 					let (mut cert, _) = handle_certificate(&server_cert_file_name, data_server_cert_file_name)?;
// 					if let Some(cert) = cert.take() {
// 						server_cert = Some(cert); // Assign the value
// 						// Do something with the server certificate
// 						// Access the fields of `cert` and perform necessary operations
// 						/*
// 												println!("Subject Country: {}", cert.subject_country);
// 												println!("Subject State: {}", cert.subject_state);
// 												println!("Subject Locality: {}", cert.subject_locality);
// 												println!("Subject Organization: {}", cert.subject_organization);
// 												println!("Subject Common Name: {}", cert.subject_common_name);
// 												println!("Issuer Country: {}", cert.issuer_country);
// 												println!("Issuer State: {}", cert.issuer_state);
// 												println!("Issuer Locality: {}", cert.issuer_locality);
// 												println!("Issuer Organization: {}", cert.issuer_organization);
// 												println!("Issuer Common Name: {}", cert.issuer_common_name);
// 												println!("Not Before: {}", cert.not_before);
// 												println!("Not After: {}", cert.not_after);
// 												println!("Is Valid: {}", cert.is_valid);
// 												println!("PKI Algorithm OID: {}", cert.pki_algorithm_oid);
// 												println!("PKI Algorithm Bytes: {}", cert.pki_algorithm_bytes);
// 												println!("PKI Algorithm Exponent: {}", cert.pki_algorithm_exponent);
// 												println!("Signature Algorithm: {}", cert.signature_algorithm);
// 												println!("Signature Value: {}", cert.signature_value);
// 												println!("Extensions authority key id: {}", cert.extensions_authority_key_identifier);
// 												println!("Extensions authority key cert issuer: {}", cert.extensions_authority_key_cert_issuer);
// 												println!("Extensions authority key cert serial: {}", cert.extensions_authority_key_cert_serial);
// 												println!("Extensions Basic Constraints: {}", cert.extensions_basic_constraints);
// 												println!("Extensions crl full name: {}", cert.extensions_crl_full_name);
// 												println!("Extensions crl reasons: {}", cert.extensions_crl_reasons);
// 												println!("Extensions crl issue: {}", cert.extensions_crl_issuer);
// 												println!("Extensions crl key usage: {}", cert.extensions_key_usage);
// 												println!("Extensions subject key identifier: {}", cert.extensions_subject_key_identifier);
// 												println!("Extensions SANS: {}", cert.extensions_subject_alternate_names);
// 
// 						 */
// 					}
// 				}
// 				Err(e) => {
// 					eprintln!("Error while decoding PEM entry {}: {}", n, e);
// 				}
// 			}
// 		}
// 
// 		//println!("\n\nIntermediate Certificate :");
// 
// 		let mut intermediate_cert: Option<IntermediateCert> = None; // Initialize as None
// 
// 
// 		let first_intermediate_cert_file_name: String = format!("{}_intermediate1.pem", domain).parse().unwrap();
// 		let data_first_intermediate_cert_file_name = std::fs::read(first_intermediate_cert_file_name.clone()).expect("Unable to read file");
// 		for (n, pem) in Pem::iter_from_buffer(&data_first_intermediate_cert_file_name).enumerate() {
// 			match pem {
// 				Ok(pem) => {
// 					let data_first_intermediate_cert_file_name = &pem.contents;
// 					//println!("Certificate [{}]", n);
// 					let (_, mut cert) = handle_certificate(&first_intermediate_cert_file_name, data_first_intermediate_cert_file_name)?;
// 
// 					if let Some(cert) = cert.take() {
// 
// 						// Do something with the intermediate certificate
// 						// Access the fields of `cert` and perform necessary operations
// 						/*
// 
// 						println!("Subject Country: {}", cert.subject_country);
// 						println!("Subject State: {}", cert.subject_state);
// 						println!("Subject Locality: {}", cert.subject_locality);
// 						println!("Subject Organization: {}", cert.subject_organization);
// 						println!("Subject Common Name: {}", cert.subject_common_name);
// 						println!("Issuer Country: {}", cert.issuer_country);
// 						println!("Issuer State: {}", cert.issuer_state);
// 						println!("Issuer Locality: {}", cert.issuer_locality);
// 						println!("Issuer Organization: {}", cert.issuer_organization);
// 						println!("Issuer Common Name: {}", cert.issuer_common_name);
// 						println!("Not Before: {}", cert.not_before);
// 						println!("Not After: {}", cert.not_after);
// 						println!("Is Valid: {}", cert.is_valid);
// 						println!("PKI Algorithm OID: {}", cert.pki_algorithm_oid);
// 						println!("PKI Algorithm Bytes: {}", cert.pki_algorithm_bytes);
// 						println!("PKI Algorithm Exponent: {}", cert.pki_algorithm_exponent);
// 						println!("Signature Algorithm: {}", cert.signature_algorithm);
// 						println!("Signature Value: {}", cert.signature_value);
// 						println!("Extensions authority key id: {}", cert.extensions_authority_key_identifier);
// 						println!("Extensions authority key cert issuer: {}", cert.extensions_authority_key_cert_issuer);
// 						println!("Extensions authority key cert serial: {}", cert.extensions_authority_key_cert_serial);
// 						println!("Extensions Basic Constraints: {}", cert.extensions_basic_constraints);
// 						println!("Extensions crl full name: {}", cert.extensions_crl_full_name);
// 						println!("Extensions crl reasons: {}", cert.extensions_crl_reasons);
// 						println!("Extensions crl issue: {}", cert.extensions_crl_issuer);
// 						println!("Extensions crl key usage: {}", cert.extensions_key_usage);
// 						println!("Extensions subject key identifier: {}", cert.extensions_subject_key_identifier);
// 						println!("Extensions SANS: {}", cert.extensions_subject_alternate_names);
// 
// 						 */
// 
// 						intermediate_cert = Some(cert); // Assign the value
// 					}
// 				}
// 				Err(e) => {
// 					eprintln!("Error while decoding PEM entry {}: {}", n, e);
// 				}
// 			}
// 		}
// 		let server_cert = server_cert.expect("No intermediate certificate found"); // Unwrap the value
// 
// 		let intermediate_cert = intermediate_cert.expect("No intermediate certificate found"); // Unwrap the value
// 
// 
// 		let cert = Cert {
// 			server: server_cert,
// 			intermediate: intermediate_cert,
// 		};
// 
// 		Ok(cert)
// 	}
// }
