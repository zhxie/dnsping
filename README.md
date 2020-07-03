# dnsping

**dnsping** is a ping tool pinging a server with DNS.

## Usage

```
dnsping <ADDRESS>

# Designate a host and use SOCKS proxy
dnsping <ADDRESS> -h <HOST> -s <ADDRESS>
```

### Args

`<ADDRESS>`: (Required) Server.

### Flags

`--help`: Prints help information.

`-i, --iterate`: Do DNS query iteratively.

`-V, --version`: Prints version information.

### Options

`-h, --host <HOST>`: Host, default as `www.google.com`.

`-p, --port <PORT>`: Port, default as `53`.

`-s, --socks-proxy <ADDRESS>`: SOCKS proxy. Only support SOCKS5 proxy.

## License

dnsping is licensed under [the MIT License](/LICENSE).
