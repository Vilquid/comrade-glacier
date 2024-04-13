use std::thread;
use std::env;
use std::sync::mpsc::channel;

pub mod logger;
pub mod schema;
pub mod bdd;
pub mod models;
mod domain;
mod get_cert;
mod ip;


use logger::log;
// use crate::bdd::add_domain;

fn main() {
  
	log("INFO", "Start of Comrade Glacier");
    //in this part I get the number of threads an create them with a channel to transmit informations between the main thread and the worker threads
    // if the number of threads is not specified, the default value is 6
    let number_of_threads = env::var("NUMBER_OF_THREADS").unwrap_or("6".to_string()).parse::<usize>().unwrap();
    //i create an array of 4 u32 to mek it easier to iterate over the possibilities of ip addresses
    let mut ip: [u32; 4] = [0, 0, 0, 0];
    //i create a channel to communicate from the workers to the main thread, i need just one because channels allows multiple senders and i have only one receiver
    let (mainspeaker, mainlistener) = channel();
    //i create a vector to store the senders to the workers and i specify that only Strings will be passed to these senders
    let mut annuaire: Vec<std::sync::mpsc::Sender<String>> = Vec::new();
    let mut worker_list: Vec<thread::JoinHandle<()>> = Vec::new();

    // i iterate to create number_of_threads - 1 workers. i create their channels and store theirs senders in the annuaire vector. i also clone the main speaker and pass it to the worker to get the results of its computation
    for _i in 0..number_of_threads {
        let (speaker, listener) = channel();
        annuaire.push(speaker);
        let speaker2 = mainspeaker.clone();
        worker_list.push(thread::spawn(move || {
            let mut message = listener.recv().unwrap();
            let mut numero = 0;
            while message != "extinction" {
                numero = numero + 1;
                let phrase = format!("adresse {}", message);
                println!("ton code devra s'exécuter ici");
                speaker2.send(phrase).unwrap();
                message = listener.recv().unwrap();
            }
        }));
    }
    
    // i create a flag to stop the iteration over ip adresses when the last possibility is reached
    let mut flag = true;
    //i iterate over the possibilities of ip addresses and pass them to the workers
    while flag{
        for i in 0..number_of_threads {
            let message = format!("{}.{}.{}.{}",ip[0],ip[1],ip[2],ip[3]);
            annuaire[i].send(message).unwrap();
            ip[3] = ip[3] + 1;
            if ip[3] == 256 {
                flag = false;
                ip[3] = 0;
                ip[2] = ip[2] + 1;
            }
            if ip[2] == 256 {
                ip[2] = 0;
                ip[1] = ip[1] + 1;
            }
            if ip[1] == 256 {
                ip[1] = 0;
                ip[0] = ip[0] + 1;
            }
            if ip[0] == 256 {
                flag = false;
                break;
            }
        }
    }

    // i send the extinction signal to the workers so they will find at the end the stop message
    for i in annuaire.iter() {
        i.send("extinction".to_string()).unwrap();
    }
    
    //when all the data are sent to the workers i wait for the them to finish their job
    for i in worker_list.into_iter() {
        i.join().unwrap();
    }
    //i drop the main speaker to hang up the channel and avoid being stuck in the last loop
    drop(mainspeaker);
    //when the workers are all deads i gather their reports and print them
    for i in mainlistener.iter() {
        println!("{}",i);
        
    }

