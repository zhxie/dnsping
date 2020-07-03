use dnsping as lib;
use lib::{Datagram, Socket, RW};
use std::net::{IpAddr, SocketAddr};

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

    let rw: Box<dyn RW + Send + Sync> = match flags.proxy {
        Some(proxy) => match proxy {
            SocketAddr::V4(_) => match Datagram::bind(proxy, "0.0.0.0:0".parse().unwrap()) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            },
            SocketAddr::V6(_) => match Datagram::bind(proxy, "[::]:0".parse().unwrap()) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            },
        },
        None => match Socket::bind("0.0.0.0:0".parse().unwrap()) {
            Ok(socket) => Box::new(socket),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };

    if let Err(ref e) = lib::ping(rw, SocketAddr::new(flags.server, flags.port), flags.host) {
        eprintln!("{}", e);
    }
}
