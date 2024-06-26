use std::fs::OpenOptions;
use std::io::Write;
use rand::Rng;
use rand::rngs::mock::StepRng;


/// # Brief
/// To log in a file named logs.txt located at ../
/// # Attributes
/// inline
/// # Parameters
/// - `level` *&str* - Level of the log. It should be INFO or ERROR.
/// - `message` *&str* - Message of the log. It should be short, simple and explicit.
/// # Return
/// **Nothing**
/// # Usage
/// mod logger;
/// use logger::log;
/// fn main()
/// {
///     log("INFO", "Short, simple and explicit message");
///     log("ERROR", format!("The IP {} is not valid", ip).as_str());
/// }
/// # Comments
/// drop(log_file); is not used because the closing curly bracket is just after the wrinting task of the function.
#[inline]
pub(crate) fn log(level: &str, message: &str)
{
	// let mut my_rng = StepRng::new(2, 1);
	// let sample: [u32; 3] = my_rng.gen();
	// Timestamp of the log
	let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S.%3f");
	
	// Create and open the log file
	let mut log_file = OpenOptions::new()
		.create(true)
		.append(true)
		.open("../logs.txt")
		.expect("ERROR - Cannot open log file 'logs.txt'");
	
	// Write in the log file
	log_file
		.write_all(format!("[{}] - {} - {}\n", level, time, message).as_ref())
		.expect("cannot write to file");
}
