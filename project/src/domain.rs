use std::process::Command;
use std::str::from_utf8;
use crate::model::{BIMI, Certificate, DANE, DMARC, Domain, IssuerDetails, MTASTS, SPF, SubjectDetails, TLSRTP, ValidityDetails};


/// # Brief
/// To get the structured bimi record of a domain
/// # Parameters
/// `domain` *String* - The domain name
/// # Return
/// `bimi_record` *BIMI* - The structured bimi record of the domain
fn bimi(domain: String) -> BIMI
{
	// Get the bimi record of the domain
	let output = Command::new("dig")
		.arg("_bimi.".to_string() + &domain)
		.arg("TXT")
		.arg("+short")
		.output()
		.expect("failed to execute process");

	// Convertit la sortie de dig en chaîne de caractères
	let output_str = String::from_utf8(output.stdout).expect("invalid utf8 string in dig output of the bimi record");

	// Déclaration d'une structure BIMIRecord
	let mut bimi_record = BIMI
	{
		used: false,
		version: "".to_string(),
		url_sender: "".to_string(),
		url_policy: "".to_string(),
		url_reputation: "".to_string(),
		hash: "".to_string(),
		s: "".to_string(),
	};

	if output_str.is_empty()
	{
		return bimi_record;
	}

	for line in output_str.lines()
	{
		if line.contains("v=BIMI")
		{
			let mut output = line.trim_matches('\"').trim();

			let parts: Vec<&str> = output.clone().split(" ").collect();

			for part in parts
			{
				let key_value: Vec<&str> = part.split(":").collect();

				if key_value.len() != 2
				{
					continue;
				}

				let key = key_value[0];
				let value = key_value[1];

				match key
				{
					"v" => bimi_record.version= value.to_string(),
					"l" => bimi_record.url_sender = value.to_string(),
					"p" => bimi_record.url_policy = value.to_string(),
					"r" => bimi_record.url_reputation = value.to_string(),
					"hash" => bimi_record.hash = value.to_string(),
					"s" => bimi_record.s = value.to_string(),
					_ => (),
				}
			}
		}
	}
	
	return bimi_record;
}

fn certificate(domain: String) -> Certificate
{
	let mut issuer_server = IssuerDetails
	{
		city: "".to_string(),
		state: "".to_string(),
		locality: "".to_string(),
		organization: "".to_string(),
		common_name: "".to_string(),
	};

	let mut signature_server = "".to_string();

	let mut validity_server = ValidityDetails {
		not_before: "".to_string(),
		not_after: "".to_string(),
		is_valid: false,
	};

	let mut subject_server = SubjectDetails {
		city: "".to_string(),
		state: "".to_string(),
		locality: "".to_string(),
		organization: "".to_string(),
		common_name: "".to_string(),
	};

	let mut extensions_server_subject_alternative_names = vec![String::new()];

	let mut issuer_intermediate = IssuerDetails {
		city: "".to_string(),
		state: "".to_string(),
		locality: "".to_string(),
		organization: "".to_string(),
		common_name: "".to_string(),
	};

	let mut signature_intermediate = "".to_string();

	let mut validity_intermediate = ValidityDetails {
		not_before: "".to_string(),
		not_after: "".to_string(),
		is_valid: false,
	};

	let mut subject_intermediate = SubjectDetails {
		city: "".to_string(),
		state: "".to_string(),
		locality: "".to_string(),
		organization: "".to_string(),
		common_name: "".to_string(),
	};

	let mut extensions_intermediate_subject_alternative_names = vec![String::new()];
	
	Certificate
	{
		used: false,
		issuer_server: IssuerDetails
		{
			city: issuer_server.city.to_string(),
			state: issuer_server.state.to_string(),
			locality: issuer_server.locality.to_string(),
			organization: issuer_server.organization.to_string(),
			common_name: issuer_server.common_name.to_string(),
		},

		signature_algorithm_server: signature_server.to_string(),

		validity_server: ValidityDetails {
			not_before: validity_server.not_before.to_string(),
			not_after: validity_server.not_after.to_string(),
			is_valid: validity_server.is_valid.to_string().parse().unwrap(),
		},
		subject_server: SubjectDetails {
			city: subject_server.city.to_string(),
			state: subject_server.state.to_string(),
			locality: subject_server.locality.to_string(),
			organization: subject_server.organization.to_string(),
			common_name: subject_server.common_name.to_string(),
		},
		
		extensions_server_subject_alternative_names,

		issuer_intermediate: IssuerDetails {
			city: issuer_intermediate.city.to_string(),
			state: issuer_intermediate.state.to_string(),
			locality: issuer_intermediate.locality.to_string(),
			organization: issuer_intermediate.organization.to_string(),
			common_name: issuer_intermediate.common_name.to_string(),
		},
		signature_algorithm_intermediate: signature_intermediate.to_string(),

		validity_intermediate: ValidityDetails {
			not_before: validity_intermediate.not_before.to_string(),
			not_after: validity_intermediate.not_after.to_string(),
			is_valid: validity_intermediate.is_valid.to_string().parse().unwrap(),
		},
		subject_intermediate: SubjectDetails {
			city: subject_intermediate.city.to_string(),
			state: subject_intermediate.state.to_string(),
			locality: subject_intermediate.locality.to_string(),
			organization: subject_intermediate.organization.to_string(),
			common_name: subject_intermediate.common_name.to_string(),
		},
		extensions_intermediate_subject_alternative_names,
	}
}

pub fn dane(domain: String) -> DANE
{
	// Get the dane record for the domain 
	let output = Command::new("dig")
		.arg("_443._tcp.".to_string() + &domain)
		.arg("TLSA")
		.arg("+short")
		.output()
		.expect("failed to execute process");

	// Convertit la sortie de dig en chaîne de caractères
	let output_str = String::from_utf8(output.stdout).expect("invalid utf8");

	// Création de la structure à renvoyer
	let mut dane_record = DANE
	{
		used: false,
		certificate_shape: 0,
		certificate_signature: false,
		hash_presence: false,
		hash: "".to_string(),
		public_key_signature: false,
	};

	// Si la sortie de dig est vide, on retourne un DANERecord vide
	if output_str.is_empty()
	{
		return dane_record;
	}
	
	println!("{}", output_str);
	// Affichage des variables pour le details 
	let words: Vec<&str> = output_str.split(' ').collect();
	
	
	if words.len() >= 5
	{
		dane_record.certificate_shape = words[0].parse().unwrap();

		if words[1] == "0"
		{
			dane_record.certificate_signature = true;
		}

		if words[1] == "1"
		{
			dane_record.public_key_signature = true;
		}

		if words[2] == "1"
		{
			dane_record.hash_presence = true;
		}

		// Si words[3] est presque aussi long qu'un hash
		if words[3].len() > 15
		{
			dane_record.hash = words[3].to_string().to_owned();
		}

		dane_record.certificate_shape = dane_record.certificate_shape.trim_matches(';').trim().to_string();
		dane_record.certificate_shape = dane_record.certificate_shape.trim_matches('\n').trim().to_string();
	}

	dane_record
}

/// # Brief
/// To get the structured dmarc record of a domain
/// # Parameters
/// `domain` *String* - The domain name
/// # Return
/// `dmarc_record` *DMARC* - The structured dmarc record of the domain
fn dmarc(domain: String) -> DMARC
{
	// Get the dmarc record of the domain
	let output = Command::new("dig")
		.arg("_dmarc.".to_string() + &domain)
		.arg("TXT")
		.output()
		.expect("Failed to execute dig");

	// Convertit la sortie de dig en chaîne de caractères
	// let output_str = str::from_utf8(&output.stdout).unwrap();

	let mut dmarc_starting = String::new();

	for line in from_utf8(&output.stdout).unwrap().lines()
	{
		if line.starts_with("_dmarc.")
		{
			dmarc_starting = line[20..].to_string();
		}
	}

	let mut dmarc_record = DMARC
	{
		used: false,
		v: "".to_string(),
		adkim: "".to_string(),
		aspf: "".to_string(),
		fo: "".to_string(),
		p: "".to_string(),
		pct: 0,
		rf: "".to_string(),
		ri: "".to_string(),
		rua: "".to_string(),
		ruf: "".to_string(),
		sp: "".to_string(),
	};

	if dmarc_starting.is_empty()
	{
		return dmarc_record;
	}

	let s = dmarc_starting;
	let v_index = s.find("v=").unwrap();
	let result = &s[v_index..];
	let parts: Vec<&str> = result.split("; ").collect();

	for part in parts
	{
		let key_value: Vec<&str> = part.split("=").collect();

		if key_value.len() != 2
		{
			continue;
		}

		let key = key_value[0];
		let value = key_value[1];

		match key
		{
			"v" => dmarc_record.v = value.to_string(),
			"p" => dmarc_record.p = value.to_string(),
			"sp" => dmarc_record.sp = value.to_string(),
			"rua" => dmarc_record.rua = value.to_string(),
			"ruf" => dmarc_record.ruf = value.to_string(),
			"ri" => dmarc_record.ri = value.to_string(),
			"rf" => dmarc_record.rf = value.to_string(),
			"pct" => dmarc_record.pct = value.to_string(),
			"aspf" => dmarc_record.aspf = value.to_string(),
			"adkim" => dmarc_record.adkim = value.to_string(),
			"fo" => dmarc_record.fo = value.to_string(),
			_ => (),
		}
	}
	
	dmarc_record.used = true;
	dmarc_record.rua = dmarc_record.rua.trim_matches('\"').trim().to_string();
	dmarc_record.rua = dmarc_record.rua.trim_matches(';').trim().to_string();
	dmarc_record.ruf = dmarc_record.ruf.trim_matches('\"').trim().to_string();
	dmarc_record.ruf = dmarc_record.ruf.trim_matches(';').trim().to_string();
	dmarc_record.fo = dmarc_record.fo.trim_matches('\"').trim().to_string();

	dmarc_record
}


/// # Brief
/// Get the mta-sts record of a domain
/// # Arguments
/// `domain` *String* - The domain name
/// # Return
/// `mta_record` *MTASTS* - The structured mta-sts record of the domain
pub(crate) fn mta(domain: String) -> MTASTS
{
	// Run the `dig` command to retrieve the MTA-STS record for the domain
	let output = Command::new("dig")
		.arg("_mta-sts.".to_string() + &domain)
		.arg("TXT")
		.arg("+short")
		.output()
		.expect("failed to execute process");

	// Convertit la sortie de dig en chaîne de caractères
	let output_str = String::from_utf8(output.stdout).expect("invalid utf8");

	let mut mta_record = MTASTS
	{
		used: false,
		version: "".to_string(),
		sn: "".to_string(),
	};

	if output_str.is_empty()
	{
		return mta_record;
	}

	let session_string = output_str;
	if session_string.contains("v=STS")
	{
		let session_string = session_string.trim_matches('\"').trim();
		let session_info: Vec<&str> = session_string.split(" ").collect();
		mta_record.version = String::from(session_info[0].split("=").collect::<Vec<&str>>()[1]);

		if session_info.len() == 1
		{
			let output = session_string.trim_matches('\"').trim();

			let parts: Vec<&str> = output.clone().split(";").collect();

			for part in parts
			{
				let key_value: Vec<&str> = part.split("=").collect();

				if key_value.len() != 2
				{
					continue;
				}

				let key = key_value[0];
				let value = key_value[1];

				match key
				{
					"v" => mta_record.version = value.to_string(),
					"id" => mta_record.sn = value.to_string(),
					_ => (),
				}
			}
		}

		if session_info.len() >= 2
		{
			mta_record.sn = String::from(session_info[1].split("=").collect::<Vec<&str>>()[1].trim_matches('\"').trim_matches(';'));
		}
	}

	if mta_record.version.contains("id") || mta_record.version.contains("ve")
	{
		mta_record.version = mta_record.version.replace("id", "");
		mta_record.version = mta_record.version.replace("ve", "");
	}
	
	mta_record.used = true;
	
	return mta_record;
}

/// # Brief
/// Get the spf record of a domain
/// # Arguments
/// `domain` *String* - The domain name
/// # Return
/// `spf_record` *SPF* - The structured spf record of the domain
fn spf(domain: String) -> SPF
{
	// Exécute la commande `dig` et récupère la sortie standard
	let output = Command::new("dig")
		.arg(domain.clone())
		.arg("TXT")
		.arg("+short")
		.output()
		.expect("échec de l'exécution de la commande `dig`");

	// Transforme la sortie en chaîne de caractères
	let output_str = String::from_utf8(output.stdout).expect("invalid utf8");
	// Sépare la chaîne de caractères en lignes
	let lines: Vec<&str> = output_str.split("\n").collect();

	// Initialise la structure qui stockera les informations du record SPF
	let mut spf_record = SPF
	{
		used: false,
		version: "".to_string(),
		mechanisms: vec![],
		qualifier: "".to_string(),
		ip: vec![],
		include: vec![],
		all: "".to_string(),
	};

	// Retour d'une structure vide si le serveur ne renvoie rien d'intéressant
	if output_str.is_empty()
	{
		return spf_record;
	}

	// Pour chaque ligne, vérifie si elle contient le record SPF
	for line in lines
	{
		if line.contains("v=spf")
		{
			// Supprime les guillemets et les espaces en début et fin de chaîne
			let mut output = line.trim_matches('\"').trim();
			let output2 = &*output.replace(":", "=");

			let parts: Vec<&str> = output2.clone().split(" ").collect();

			for part in parts
			{
				let key_value: Vec<&str> = part.split("=").collect();

				if key_value.len() != 2
				{
					continue;
				}

				let key = key_value[0];
				let value = key_value[1];

				match key
				{
					"v" => spf_record.version = value.to_string(),
					"ip4" => spf_record.ip.push(value.to_string()),
					"include" => spf_record.include.push(value.to_string()),
					"redirect" => spf_record.include.push(value.to_string()),
					"all" => spf_record.all = value.to_string(),
					"mechanism" => spf_record.mechanisms.push(value.to_string()),
					"qualifier" => spf_record.qualifier = value.to_string(),
					_ => (),
				}
			}
		}
	}
	
	spf_record.used = true;
	
	spf_record
}

/// # Brief
/// Get the tls-rpt record of a domain
/// # Arguments
/// `domain` *String* - The domain name
/// # Return
/// `tls_record` *TLSRTP* - The structured tls-rpt record of the domain
fn tls_rtp(domain: String) -> TLSRTP
{
	// Run the `dig` command to retrieve the TLS-RPT record for the domain
	let output = Command::new("dig")
		.arg("_report._tls.".to_string() + &domain)
		.arg("TXT")
		.arg("+short")
		.output()
		.expect("failed to execute process");

	// Convertit la sortie de dig en chaîne de caractères
	let output_str = String::from_utf8(output.stdout).expect("invalid utf8");

	let mut tls_record = TLSRTP
	{
		used: false,
		v: "".to_string().to_owned(),
		rua: "".to_string().to_owned(),
	};

	if output_str.is_empty()
	{
		return tls_record;
	}

	for line in output_str.lines()
	{
		if line.contains("v=TLSRPT")
		{
			let session_string = line.trim_matches('\"').trim();
			// let session_info: Vec<&str> = session_string.split(" ").collect();

			let session_string = session_string.replace(" ", "");

			let parts: Vec<&str> = session_string.split(";").collect();

			for part in parts
			{
				let key_value: Vec<&str> = part.split("=").collect();

				if key_value.len() != 2
				{
					continue;
				}

				let key = key_value[0];
				let value = key_value[1];

				match key
				{
					"v" => tls_record.v = value.to_string(),
					"rua" => tls_record.rua = value.to_string(),
					_ => (),
				}
			}
		}
	}
	
	tls_record.used = true;
	
	return tls_record;
}

/// # Brief
/// To get the structured domain record of a domain
/// # Parameters
/// `domain` *&str* - The domain name
/// # Usage
/// let domain = domain("example.com");
/// # Return
/// `domain_record` *Domain* - The structured domain record of the domain
pub(crate) fn dns(domain: &str) -> Domain
{
	let domain_struct = String::from(&domain);
	let domain_function = domain_struct.clone();
	
	let domain_record = Domain
	{
		id: 0,
		domain: domain_struct.clone(),
		bimi: bimi(domain_function.clone()),
		certificate: (),
		dane: dane(domain_function.clone()),
		dmarc: dmarc(domain_function.clone()),
		mta: mta(domain_function.clone()),
		tls_rpt: tls_rtp(domain_function.clone()),
		spf: spf(domain_function.clone()),
	};
	
	domain_record
}

