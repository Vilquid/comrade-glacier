use std::env;
use std::sync::mpsc::channel;
use std::thread;
use dotenv::dotenv;

use logger::log;
use crate::ip::save_last_scanned_ip;

pub mod logger;
pub mod schema;
pub mod bdd;
pub mod models;
mod domain;
mod get_cert;
mod ip;


fn main()
{
	log("INFO", "Start of Comrade Glacier");

	//in this part I get the number of threads an create them with a channel to transmit informations between the main thread and the worker threads
	// if the number of threads is not specified, the default value is 6
	let number_of_threads = env::var("NUM_THREADS").unwrap_or("10".to_string()).parse::<usize>().unwrap();

	// Creation of an array to make it easier to iterate over the possibilities of ip addresses
	let mut ip: [u32; 4] = [0, 0, 0, 0];

	if dotenv().ok().is_some()
	{
		let last_ip = ip::last_scanned_ip();
		let last_ip: Vec<&str> = last_ip.split('.').collect();
		ip[0] = last_ip[0].parse::<u32>().unwrap();
		ip[1] = last_ip[1].parse::<u32>().unwrap();
		ip[2] = last_ip[2].parse::<u32>().unwrap();
		ip[3] = last_ip[3].parse::<u32>().unwrap();
	}

	// Creation of a channel to communicate from the workers to the main thread, i need just one because channels allows multiple senders and i have only one receiver
	let (mainspeaker, _mainlistener) = channel();

	//i create a vector to store the senders to the workers and i specify that only Strings will be passed to these senders
	let mut annuaire: Vec<std::sync::mpsc::Sender<String>> = Vec::new();
	let mut worker_list: Vec<thread::JoinHandle<()>> = Vec::new();

	// i iterate to create number_of_threads - 1 workers. i create their channels and store theirs senders in the annuaire vector. i also clone the main speaker and pass it to the worker to get the results of its computation
	for _i in 0..number_of_threads
	{
		let (speaker, listener) = channel();
		annuaire.push(speaker);
		let speaker2 = mainspeaker.clone();
		worker_list.push(thread::spawn(move || {
			let mut message = listener.recv().unwrap();

			#[allow(unused_variables)]
				let mut numero = 0;

			while message != "extinction"
			{
				numero += 1;
				let phrase = message.to_string();
				// println!("Worker {}", phrase);
				ip::ip(message.clone());

				let _ = save_last_scanned_ip(message.to_string());

				speaker2.send(phrase).unwrap();
				message = listener.recv().unwrap();
			}
		}));
	}

	// i create a flag to stop the iteration over ip adresses when the last possibility is reached
	let mut flag = true;

	//i iterate over the possibilities of ip addresses and pass them to the workers
	while flag
	{
		#[allow(clippy::needless_range_loop)]
			for i in 0..number_of_threads
			{
				let message = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
				annuaire[i].send(message).unwrap();

				ip[3] += 1;
				if ip[3] == 254
				{
					ip[3] = 1;
					ip[2] += 1;
				}
				if ip[2] == 255
				{
					println!("Current IP : {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
					ip[2] = 0;
					ip[1] += 1;
				}
				if ip[1] == 255
				{
					// println!("Current IP : {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
					ip[1] = 0;
					ip[0] += 1;
				}
				if ip[0] == 256
				{
					// println!("Current IP : {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
					flag = false;
					break;
				}
			}
	}

	// i send the extinction signal to the workers so they will find at the end the stop message
	for i in annuaire.iter()
	{
		i.send("extinction".to_string()).unwrap();
	}

	// when all the data are sent to the workers i wait for the them to finish their job
	for i in worker_list.into_iter()
	{
		i.join().unwrap();
	}
	// I drop the main speaker to hang up the channel and avoid being stuck in the last loop
	drop(mainspeaker);

	log("INFO", "End of Comrade Glacier");
}

