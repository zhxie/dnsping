use clap::{crate_description, crate_version, Clap};
use ctrlc;
use dns_parser::{Builder, QueryClass, QueryType};
use dnsping as lib;
use lib::{Datagram, Socket, RW};
use std::clone::Clone;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clap, Clone, Debug, Eq, Hash, PartialEq)]
#[clap(
    version = crate_version!(),
    about = crate_description!()
)]
struct Flags {
    #[clap(name = "ADDRESS", about = "Server")]
    pub server: IpAddr,
    #[clap(long, short, about = "Do query iteratively")]
    pub iterate: bool,
    #[clap(long, short, about = "Port", value_name = "PORT", default_value = "53")]
    pub port: u16,
    #[clap(
        long,
        short = "H",
        about = "Host",
        value_name = "HOST",
        default_value = "www.google.com"
    )]
    pub host: String,
    #[clap(
        long = "socks-proxy",
        short = "s",
        about = "SOCKS proxy",
        value_name = "ADDRESS"
    )]
    pub proxy: Option<SocketAddr>,
    #[clap(
        long,
        short,
        about = "Number of queries to send",
        value_name = "VALUE",
        default_value = "0"
    )]
    pub count: usize,
    #[clap(
        long,
        short = "I",
        about = "Wait between sending each packet",
        value_name = "VALUE",
        default_value = "1000"
    )]
    pub interval: u64,
    #[clap(
        long = "timeout",
        short = "w",
        about = "Timeout to wait for each response",
        value_name = "VALUE",
        default_value = "1000"
    )]
    pub timeout: u64,
}

fn main() {
    // Parse arguments
    let flags = Flags::parse();
    if let Some(ref proxy) = flags.proxy {
        match proxy {
            SocketAddr::V4(proxy) => {
                if let IpAddr::V6(server) = flags.server {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                }
            }
            SocketAddr::V6(proxy) => {
                if let IpAddr::V4(server) = flags.server {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                }
            }
        }
    }
    let addr = SocketAddr::new(flags.server, flags.port);

    // Bind socket
    let local: SocketAddr = match flags.server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW> = match flags.proxy {
        Some(proxy) => match Datagram::bind(proxy, local) {
            Ok(datagram) => Box::new(datagram),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
        None => match Socket::bind(local) {
            Ok(socket) => Box::new(socket),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };
    if flags.timeout != 0 {
        if let Err(ref e) = rw.set_read_timeout(Some(Duration::from_millis(flags.timeout))) {
            eprintln!("{}", e);
            return;
        }
    }

    // Handle Ctrl+C
    let (tx, rx) = mpsc::channel::<()>();
    let tx_cloned = tx.clone();
    ctrlc::set_handler(move || {
        let _ = tx_cloned.send(());
    })
    .unwrap();

    // Ping
    let send = Arc::new(AtomicUsize::new(0));
    let send_cloned = Arc::clone(&send);
    let recv = Arc::new(AtomicUsize::new(0));
    let recv_cloned = Arc::clone(&recv);
    let latency_total = Arc::new(AtomicU64::new(0));
    let latency_total_cloned = Arc::clone(&latency_total);
    let latency_min = Arc::new(AtomicU64::new(u64::MAX));
    let latency_min_cloned = Arc::clone(&latency_min);
    let latency_max = Arc::new(AtomicU64::new(0));
    let latency_max_cloned = Arc::clone(&latency_max);
    thread::spawn(move || {
        // Psuedo DNS query
        let is_ipv6 = match flags.server {
            IpAddr::V4(_) => false,
            IpAddr::V6(_) => true,
        };
        let mut query = Builder::new_query(0, true);
        if is_ipv6 {
            query.add_question(&flags.host, false, QueryType::AAAA, QueryClass::IN);
        } else {
            query.add_question(&flags.host, false, QueryType::A, QueryClass::IN);
        }
        let buffer = match query.build() {
            Ok(buffer) => buffer,
            Err(_) => {
                eprintln!("{}", io::Error::from(io::ErrorKind::InvalidData));
                let _ = tx.send(());
                return;
            }
        };
        println!(
            "PING {} for {} {} bytes of data.",
            addr,
            flags.host,
            buffer.len()
        );

        loop {
            let id = send.fetch_add(1, Ordering::Relaxed);
            let instant = Instant::now();

            // Ping
            match lib::ping(&rw, addr, id as u16, flags.iterate, &flags.host) {
                Ok((size, duration)) => {
                    println!(
                        "{} bytes from {}: id={} time={:.2} ms",
                        size,
                        addr,
                        id,
                        duration.as_micros() as f64 / 1000.0
                    );

                    recv.fetch_add(1, Ordering::Relaxed);
                    let duration = duration.as_micros() as u64;
                    latency_total.fetch_add(duration, Ordering::Relaxed);
                    if latency_max.load(Ordering::Relaxed) < duration {
                        latency_max.store(duration, Ordering::Relaxed);
                    }
                    if latency_min.load(Ordering::Relaxed) > duration {
                        latency_min.store(duration, Ordering::Relaxed);
                    }
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::TimedOut => {
                        println!("{}", e);
                    }
                    _ => {
                        eprintln!("{}", e);
                        let _ = tx.send(());
                        return;
                    }
                },
            };

            // Reach max send count
            if id == flags.count.checked_sub(1).unwrap_or(usize::MAX) {
                let _ = tx.send(());
                return;
            }

            // Sleep until interval
            let elapsed = instant.elapsed();
            let remain = Duration::from_millis(flags.interval)
                .checked_sub(Duration::from_millis(elapsed.as_millis() as u64))
                .unwrap_or(Duration::from_millis(0));
            thread::sleep(remain);
        }
    });

    // Close gracefully
    match rx.recv() {
        Ok(_) => {
            let send = send_cloned.load(Ordering::Relaxed);
            let recv = recv_cloned.load(Ordering::Relaxed);
            let lost = send
                .checked_sub(recv)
                .unwrap_or_else(|| send + (usize::MAX - recv));
            let loss_rate = match send {
                0 => 0.0,
                _ => (lost as f64) / (send as f64) * 100.0,
            };
            let latency_total = latency_total_cloned.load(Ordering::Relaxed);
            let latency_avg = latency_total / send as u64;
            let latency_min = latency_min_cloned.load(Ordering::Relaxed);
            let latency_max = latency_max_cloned.load(Ordering::Relaxed);

            println!("--- {} ping statistics ---", addr);
            println!(
                "{} packets transmitted, {} received, {:.2}% packet loss",
                send, recv, loss_rate
            );

            if recv != 0 {
                println!(
                    "rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
                    latency_min as f64 / 1000.0,
                    latency_avg as f64 / 1000.0,
                    latency_max as f64 / 1000.0
                );
            }
        }
        Err(_) => unreachable!(),
    }
}
