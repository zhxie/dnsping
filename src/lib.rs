use clap::{crate_description, crate_version, Clap};
use dns_parser::{Builder, Packet, QueryClass, QueryType};
use socks::{Socks5Datagram, TargetAddr};
use std::clone::Clone;
use std::cmp;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Represents the flags of the application.
#[derive(Clap, Clone, Debug, Eq, Hash, PartialEq)]
#[clap(
    version = crate_version!(),
    about = crate_description!()
)]
pub struct Flags {
    #[clap(long = "no-stat", about = "Disable statistics")]
    pub no_stat: bool,
    #[clap(name = "ADDRESS", about = "Server")]
    pub server: IpAddr,
    #[clap(long, short, about = "Port", value_name = "PORT", default_value = "53")]
    pub port: u16,
    #[clap(
        long,
        short,
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
}

/// Parses the arguments.
pub fn parse() -> Flags {
    Flags::parse()
}

/// Represents an socket which can send data to and receive data from a certain address.
pub trait RW {
    /// Sends data on the socket to the given address.
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    /// Receives a single datagram message on the socket.
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}

/// Represents an UDP datagram, containing a TCP stream keeping the SOCKS proxy alive and an UDP
/// socket sending and receiving data.
pub struct Datagram {
    datagram: Socks5Datagram,
}

impl Datagram {
    /// Creates a new `Datagram`.
    pub fn bind(proxy: SocketAddr, addr: SocketAddr) -> Result<Datagram> {
        let datagram = Socks5Datagram::bind(proxy, addr)?;

        Ok(Datagram { datagram })
    }
}

impl RW for Datagram {
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.datagram.send_to(buf, addr)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (size, addr) = self.datagram.recv_from(buf)?;

        return match addr {
            TargetAddr::Ip(addr) => Ok((size, addr)),
            _ => unreachable!(),
        };
    }
}

/// Represents an UDP socket.
pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    /// Creates a new `Socket`.
    pub fn bind(addr: SocketAddr) -> Result<Socket> {
        let socket = UdpSocket::bind(addr)?;

        Ok(Socket { socket })
    }
}

impl RW for Socket {
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.socket.send_to(buf, addr)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }
}

/// Represents the period sending ping in milliseconds. After a new ping is sent, all unreceived
/// previous ping will be considered as timed out.
const PERIOD: u64 = 1000;

/// Pings the DNS server.
pub fn ping(
    rw: Box<dyn RW + Send + Sync>,
    stopped: Arc<AtomicBool>,
    addr: SocketAddr,
    host: String,
) -> Result<()> {
    let is_ipv6 = match addr {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(_) => true,
    };

    let a_rw = Arc::new(rw);
    let a_rw_cloned = Arc::clone(&a_rw);

    let time_map: HashMap<u16, Instant> = HashMap::new();
    let a_time_map = Arc::new(Mutex::new(time_map));
    let a_time_map_cloned = Arc::clone(&a_time_map);

    let send = AtomicUsize::new(0);
    let a_send = Arc::new(send);
    let a_send_cloned = Arc::clone(&a_send);

    // Psuedo DNS query
    let mut query = Builder::new_query(0, true);
    if is_ipv6 {
        query.add_question(&host, false, QueryType::AAAA, QueryClass::IN);
    } else {
        query.add_question(&host, false, QueryType::A, QueryClass::IN);
    }
    let buffer = match query.build() {
        Ok(buffer) => buffer,
        Err(_) => {
            return Err(Error::from(ErrorKind::InvalidData));
        }
    };
    println!("PING {} for {} {} bytes of data.", addr, host, buffer.len());

    // Send query
    thread::spawn(move || {
        let mut id = 0;
        loop {
            id += 1;
            // Create a DNS query
            let mut query = Builder::new_query(id, true);
            if is_ipv6 {
                query.add_question(&host, false, QueryType::AAAA, QueryClass::IN);
            } else {
                query.add_question(&host, false, QueryType::A, QueryClass::IN);
            }
            let buffer = query.build().unwrap();

            // Update timestamp
            a_time_map.lock().unwrap().insert(id, Instant::now());

            // Send
            match a_rw.send_to(buffer.as_slice(), addr) {
                Ok(_) => {
                    a_send.fetch_add(1, Ordering::Relaxed);
                }
                Err(ref e) => eprintln!("{}", e),
            }

            // Wait for a certain time
            thread::sleep(Duration::from_millis(PERIOD));
        }
    });

    let mut buffer = vec![0u8; u16::MAX as usize];
    let mut recv = 0;
    let mut min = u128::MAX;
    let mut max = u128::MIN;
    let mut total = 0;
    loop {
        if stopped.load(Ordering::Relaxed) {
            break;
        }
        // Receive
        match a_rw_cloned.recv_from(buffer.as_mut_slice()) {
            Ok((size, a)) => {
                if size > 0 && a == addr {
                    // Parse the DNS answer
                    if let Ok(ref packet) = Packet::parse(&buffer[..size]) {
                        let id = packet.header.id;
                        if let Some(instant) = a_time_map_cloned.lock().unwrap().get(&id) {
                            let elapsed = instant.elapsed().as_micros();
                            min = cmp::min(min, elapsed);
                            max = cmp::max(max, elapsed);
                            total += elapsed;

                            let elapsed = elapsed as f64;
                            let elapsed = elapsed / 1000.0;
                            recv += 1;
                            let send = a_send_cloned.load(Ordering::Relaxed);
                            let diff = send
                                .checked_sub(recv)
                                .unwrap_or_else(|| send + (usize::MAX - recv));
                            // Log
                            if recv == send {
                                println!(
                                    "{} bytes from {}: id={} time={:.2} ms",
                                    size, a, id, elapsed
                                );
                            } else {
                                println!(
                                    "{} bytes from {}: id={} time={:.2} ms ({} packet loss)",
                                    size, a, id, elapsed, diff
                                );
                            }
                        }
                        a_time_map_cloned.lock().unwrap().remove(&id);
                    }
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    let send = a_send_cloned.load(Ordering::Relaxed);
    println!("--- {} ping statistics ---", addr);
    println!(
        "{} packets transmitted, {} received, {:.2}% packet loss",
        send,
        recv,
        ((send
            .checked_sub(recv)
            .unwrap_or_else(|| send + (usize::MAX - recv))) as f64)
            / (send as f64)
            * 100.0
    );
    if recv != 0 {
        println!(
            "rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
            min as f64 / 1000.0,
            (total as f64 / 1000.0) / (recv as f64),
            max as f64 / 1000.0
        );
    }

    Ok(())
}
