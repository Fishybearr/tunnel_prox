# Roxy Tunneling Proxy
Simple tunneling proxy for encrypting and obfuscating network traffic
through a private server

## Quickstart
1) download roxy.py from
```
https://github.com/Fishybearr/tunnel_prox/tree/main
```

2) run this in a terminal
```bash
python roxy.py client ECC local
```
3) run this in a different terminal
```bash
python roxy.py server ECC local
```
4) Run this in a 3rd terminal
```bash
curl -v -x http://127.0.0.1:8888 https://www.weatherbuddy.org:443/roxy.html
```
5) Your curl terminal should respond with
```html
<p>Roxy Connection Successful</p>
```


## Usage
```bash
python roxy.py <host> <handshake_mode> <execution_mode> <optional remote_host_address> <optional password>
```
## Arguments
### host (string)
client

    client mode

server

    server mode
### handshake_mode (string)
PBKD

    password based key derivation

ECC

    elliptical curve

### execution_mode (string)

local

    local mode runs the client and server proxies on the same system allowing for testing on one machine


remote

    remote mode runs the client proxy on the client device and the remote proxy on another device on the same local network.This is a more realistic simulation as all traffic in forwarded from the client to the remote proxy server

### remote_host_address (string) (optional)
     If PBDK is used for handshake_mode then a password string is required for generating a key used to encrypt/decrypt traffic.
     
     If no password is provided, the default password of "TestPass" will be used

### password (string) (optional)
     If PBDK is used for handshake_mode then a password string is required for generating a key used to encrypt/decrypt traffic.
     
     If no password is provided, the default password of "TestPass" will be used

## Testing
I've found 2 decent methods for testing roxy

### curl

### firefox