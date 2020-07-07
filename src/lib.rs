//! Ping a server with DNS.

use dns_parser::{Builder, Packet, QueryClass, QueryType};
use socks::{Socks5Datagram, TargetAddr};
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Represents an socket which can send data to and receive data from a certain address.
pub trait RW: Send + Sync {
    /// Sends data on the socket to the given address.
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    /// Receives a single datagram message on the socket.
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Sets the read timeout to the timeout specified.
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()>;

    /// Sets the write timeout to the timeout specified.
    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()>;

    /// Returns the read timeout of this socket.
    fn read_timeout(&self) -> Result<Option<Duration>>;

    /// Returns the write timeout of this socket.
    fn write_timeout(&self) -> Result<Option<Duration>>;
}

/// Represents an UDP datagram, containing a TCP stream keeping the SOCKS proxy alive and an UDP
/// socket sending and receiving data.
#[derive(Debug)]
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

    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.datagram.get_ref().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.datagram.get_ref().set_write_timeout(dur)
    }

    fn read_timeout(&self) -> Result<Option<Duration>> {
        self.datagram.get_ref().read_timeout()
    }

    fn write_timeout(&self) -> Result<Option<Duration>> {
        self.datagram.get_ref().write_timeout()
    }
}

/// Represents an UDP socket.
#[derive(Debug)]
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

    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.socket.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.socket.set_write_timeout(dur)
    }

    fn read_timeout(&self) -> Result<Option<Duration>> {
        self.socket.read_timeout()
    }

    fn write_timeout(&self) -> Result<Option<Duration>> {
        self.socket.write_timeout()
    }
}

/// Pings a DNS server.
pub fn ping(
    rw: &Box<dyn RW>,
    addr: SocketAddr,
    id: u16,
    iterate: bool,
    host: &String,
) -> Result<(usize, Duration)> {
    let is_ipv6 = match addr {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(_) => true,
    };

    // DNS query
    let mut query = Builder::new_query(id, iterate);
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

    // Send query
    let mut recv_buffer = vec![0u8; u16::MAX as usize];
    let instant = Instant::now();
    let _ = rw.send_to(buffer.as_slice(), addr)?;

    // Receive
    loop {
        match rw.recv_from(recv_buffer.as_mut_slice()) {
            Ok((size, a)) => {
                if size <= 0 {
                    return Err(Error::from(ErrorKind::UnexpectedEof));
                } else {
                    if a == addr {
                        // Parse the DNS answer
                        if let Ok(packet) = Packet::parse(&recv_buffer[..size]) {
                            if packet.header.id == id {
                                return Ok((size, instant.elapsed()));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}
