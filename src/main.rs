use ctrlc;
use dns_parser::{Builder, QueryClass, QueryType};
use dnsping as lib;
use lib::{Datagram, Socket, RW};
use std::clone::Clone;
use std::fmt::Display;
use std::io;
use std::net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(Debug)]
enum ResolvableAddrParseError {
    AddrParseError(AddrParseError),
    ResolveError(io::Error),
}

impl Display for ResolvableAddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvableAddrParseError::AddrParseError(e) => write!(f, "{}", e),
            ResolvableAddrParseError::ResolveError(e) => write!(f, "{}", e),
        }
    }
}

impl From<AddrParseError> for ResolvableAddrParseError {
    fn from(s: AddrParseError) -> Self {
        ResolvableAddrParseError::AddrParseError(s)
    }
}

impl From<io::Error> for ResolvableAddrParseError {
    fn from(s: io::Error) -> Self {
        ResolvableAddrParseError::ResolveError(s)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ResolvableSocketAddr {
    addr_v4: Option<SocketAddrV4>,
    addr_v6: Option<SocketAddrV6>,
    alias: Option<String>,
}

impl ResolvableSocketAddr {
    fn addr_v4(&self) -> Option<SocketAddrV4> {
        self.addr_v4
    }

    fn addr_v6(&self) -> Option<SocketAddrV6> {
        self.addr_v6
    }
}

impl Display for ResolvableSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.addr_v4.is_some() && self.addr_v6.is_some() {
            write!(f, "{}/{}", self.addr_v4.unwrap(), self.addr_v6.unwrap())?;
        } else if self.addr_v4.is_some() {
            write!(f, "{}", self.addr_v4.unwrap())?;
        } else if self.addr_v6.is_some() {
            write!(f, "{}", self.addr_v6.unwrap())?;
        } else {
            unreachable!()
        }
        match &self.alias {
            Some(alias) => write!(f, " ({})", alias),
            None => Ok(()),
        }
    }
}

impl FromStr for ResolvableSocketAddr {
    type Err = ResolvableAddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let has_alias;
        let (addr_v4, addr_v6) = match s.parse() {
            Ok(addr) => {
                has_alias = false;

                match addr {
                    SocketAddr::V4(addr_v4) => (Some(addr_v4), None),
                    SocketAddr::V6(addr_v6) => (None, Some(addr_v6)),
                }
            }
            Err(e) => {
                has_alias = true;

                let v = s.split(":").collect::<Vec<_>>();
                if v.len() != 2 {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let port = match v[1].parse() {
                    Ok(port) => port,
                    Err(_) => return Err(ResolvableAddrParseError::from(e)),
                };

                let mut ip_v4 = None;
                let mut ip_v6 = None;
                match dns_lookup::lookup_host(v[0]) {
                    Ok(addrs) => {
                        for addr in addrs {
                            match addr {
                                IpAddr::V4(addr_v4) => {
                                    if ip_v4.is_none() {
                                        ip_v4 = Some(addr_v4);
                                    }
                                }
                                IpAddr::V6(addr_v6) => {
                                    if ip_v6.is_none() {
                                        ip_v6 = Some(addr_v6);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => return Err(ResolvableAddrParseError::from(e)),
                };

                if ip_v4.is_none() && ip_v6.is_none() {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let addr_v4 = match ip_v4 {
                    Some(ip_v4) => Some(SocketAddrV4::new(ip_v4, port)),
                    None => None,
                };
                let addr_v6 = match ip_v6 {
                    Some(ip_v6) => Some(SocketAddrV6::new(ip_v6, port, 0, 0)),
                    None => None,
                };

                (addr_v4, addr_v6)
            }
        };

        let alias = match has_alias {
            true => Some(String::from_str(s).unwrap()),
            false => None,
        };
        Ok(ResolvableSocketAddr {
            addr_v4,
            addr_v6,
            alias,
        })
    }
}

#[derive(StructOpt, Clone, Debug, Eq, Hash, PartialEq)]
#[structopt(about)]
struct Flags {
    #[structopt(name = "ADDRESS", help = "Server")]
    pub server: IpAddr,
    #[structopt(long, short, help = "Do query iteratively")]
    pub iterate: bool,
    #[structopt(
        long,
        short,
        help = "Port",
        value_name = "PORT",
        default_value = "53",
        display_order(0)
    )]
    pub port: u16,
    #[structopt(
        long,
        short = "H",
        help = "Host",
        value_name = "HOST",
        default_value = "www.google.com",
        display_order(1)
    )]
    pub host: String,
    #[structopt(
        long = "socks-proxy",
        short = "s",
        help = "SOCKS proxy",
        value_name = "ADDRESS",
        display_order(3)
    )]
    pub proxy: Option<ResolvableSocketAddr>,
    #[structopt(
        long,
        help = "Username",
        value_name = "VALUE",
        requires("password"),
        display_order(4)
    )]
    pub username: Option<String>,
    #[structopt(
        long,
        help = "Password",
        value_name = "VALUE",
        requires("username"),
        display_order(5)
    )]
    pub password: Option<String>,
    #[structopt(
        long,
        short,
        help = "Number of queries to send",
        value_name = "VALUE",
        default_value = "0",
        display_order(6)
    )]
    pub count: usize,
    #[structopt(
        long,
        short = "I",
        help = "Wait between sending each packet",
        value_name = "VALUE",
        default_value = "1000",
        display_order(7)
    )]
    pub interval: u64,
    #[structopt(
        long,
        short = "w",
        help = "Timeout to wait for each response",
        value_name = "VALUE",
        default_value = "1000",
        display_order(8)
    )]
    pub timeout: u64,
}

fn main() {
    // Parse arguments
    let flags = Flags::from_args();
    let proxy = match &flags.proxy {
        Some(proxy) => match flags.server {
            IpAddr::V4(server) => match proxy.addr_v4() {
                Some(addr_v4) => Some(SocketAddr::V4(addr_v4)),
                None => {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                    return;
                }
            },
            IpAddr::V6(server) => match proxy.addr_v6() {
                Some(addr_v6) => Some(SocketAddr::V6(addr_v6)),
                None => {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                    return;
                }
            },
        },
        None => None,
    };
    let addr = SocketAddr::new(flags.server, flags.port);

    // Bind socket
    let local: SocketAddr = match flags.server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW> = match proxy {
        Some(proxy) => {
            let auth = match flags.username.clone() {
                Some(username) => Some((username, flags.password.clone().unwrap())),
                None => None,
            };
            match Datagram::bind(proxy, local, auth) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            }
        }
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
            let id = send
                .fetch_add(1, Ordering::Relaxed)
                .checked_add(1)
                .unwrap_or(0);
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
            if id == flags.count {
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
