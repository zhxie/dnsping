use ctrlc;
use dnsping as lib;
use lib::{Datagram, Message, Socket, RW};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;

fn main() {
    // Parse arguments
    let flags = lib::parse();
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

    // Bind socket
    let local: SocketAddr = match flags.server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW + Send + Sync> = match flags.proxy {
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

    // Handle Ctrl+C
    let (tx, rx) = mpsc::channel::<Message>();
    let tx_cloned = tx.clone();
    ctrlc::set_handler(move || {
        if let Err(_) = tx.send(Message::Close) {
            return;
        }
    })
    .unwrap();

    if let Err(ref e) = lib::ping(
        rw,
        tx_cloned,
        rx,
        SocketAddr::new(flags.server, flags.port),
        flags.host,
    ) {
        eprintln!("{}", e);
    }
}
