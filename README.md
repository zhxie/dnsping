# dnsping

**dnsping** is a ping tool pinging a server with DNS.

## Usage

```
dnsping <ADDRESS>

# Designate a host and use SOCKS proxy
dnsping <ADDRESS> -H <HOST> -s <ADDRESS>
```

### Args

`<ADDRESS>`: (Required) Server.

### Flags

`-h, --help`: Prints help information.

`-i, --iterate`: Do query iteratively.

`-V, --version`: Prints version information.

### Options

`-p, --port <PORT>`: Port, default as `53`.

`-H, --host <HOST>`: Host, default as `www.google.com`.

`-s, --socks-proxy <ADDRESS>`: SOCKS proxy. Only support SOCKS5 proxy.

`--username <VALUE>`: Username. This value should be set only when the SOCKS5 server requires the username/password authentication.

`--password <VALUE>`: Password. This value should be set only when the SOCKS5 server requires the username/password authentication.

`-c, --count <VALUE>`: Number of queries to send, `0` as sending constantly without limit, default as `0`.

`-I, --interval <VALUE>`: Wait between sending each packet, default as `1000` ms.

`-w, --timeout <VALUE>`: Timeout to wait for each response, `0` as no timeout, default as `1000` ms.

## License

dnsping is licensed under [the MIT License](/LICENSE).
