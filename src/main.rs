use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;

// max port we can sniff
const MAX: u16 = 65535;


struct Arguments {
    flag : String,
    ipaddr: IpAddr, // Enum V4 or V6
    threads: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        // we will return either the argument struct or if panicked, a string slice (we need to add the 'static lifetime
        // to ensure that we can ensure we can send the error message to the main function) - remember Result is a generic of <T,E>
            if args.len() < 2 {
                return Err("not enough arguments");
            } else if args.len() > 4 {
                return Err("too many arguments");
            }

            let f = args[1].clone();
            if let Ok(ipaddr) = IpAddr::from_str(&f) {
                // if-let binding to destruct IpAddr::from_str, which returns a Result
                // match IpAddr:: [...] and see if it's an ok. inside the Ok we have the Argument type, which is ipaddr, so
                // we can destruct it
                return Ok(Arguments {flag: String::from(""), ipaddr, threads: 4})
            } else {
                let flag = args[1].clone();
                if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                    println!("Usage: -j to select how many threads you want
                    \r\n    -h or -help to show this help message");

                    return Err("help");

                } else if  flag.contains("-h") || flag.contains("-help") {
                    return Err("too many arguments");

                } else if flag.contains("-j") {
                    let ipaddr = match IpAddr::from_str(&args[3]) {
                        Ok(s) => s,
                        Err(_) => return Err("not a valid IPADDR")
                    };

                    let threads = match args[2].parse::<u16>() {
                        // parse transform the string method into u16
                        Ok(s) => s,
                        Err(_) => return Err("failed to parse thread number")
                    };

                    return Ok(Arguments{threads, flag, ipaddr});
                } else {
                    return Err("Invalid syntax");
                }
            }
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    
    // start the scan for each thread with the thread number 
    let mut port: u16 = start_port + 1;
    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap(); // we flush all the print statements if the port is open
                tx.send(port).unwrap();
            },
            Err(_) => {}
        }

        if (MAX - port) <= num_threads {
            break;
        }

        // we'll keep increasing the number of ports to sniff according to the num of threads
        port += num_threads;
    }

}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(
        // this call takes a closure, which we define here directly and takes the error parameter
        |err| {
            if err.contains("help") {
                process::exit(0)
            } else {
                eprintln!("{} problem parsing arguments: {}", program, err);
                process::exit(0)
            }
        }
    );

    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;

    let (tx, rx) = channel();

    for i in 0..num_threads {
        // we clone the transmitter, so each thread has its own transmitter:
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i, addr, num_threads);
        });
    }
        let mut out = vec![];
        
        // Important: we need to drop the last tx, otherwise it will keep waiting for another message in the channel!
        drop(tx);
        for p in &rx {
            // push the ports detected open in our receiver
            out.push(p);
        }

        println!("");
        out.sort();
        for v in out {
            println!("{} is open", v);
        }


    

}


