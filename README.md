# Roxy Tunneling Proxy
Simple tunneling proxy for encrypting and obfuscating network traffic
through a private server

## Dependencies
- python
- pycryptodome

## Quickstart
1) download roxy.py from
```
https://github.com/Fishybearr/tunnel_prox/tree/main
```
2) install dependencies

[!WARNING] 
pycryptodome can conflict with the deprecated Crypto package

2) run this in a terminal
```bash
python roxy.py client ECC local
```
3) run this in a 2nd terminal
```bash
python roxy.py server ECC local
```
4) run this in a 3rd terminal
```bash
curl -x http://127.0.0.1:8888 https://www.weatherbuddy.org:443/roxy.html
```
5) Your 3rd terminal should respond with
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

- client mode

server

- server mode
### handshake_mode (string)
PBKD

- password based key derivation

ECC

- elliptical curve

### execution_mode (string)

local

- local mode runs the client and server proxies on the same system allowing for testing on one machine


remote

- remote mode runs the client proxy on the client device and the remote proxy on another device on the same local network.This is a more realistic simulation as all traffic in forwarded from the client to the remote proxy server

### remote_host_address (string) (optional)
- This is the ip address of your server

- Will automatically be hosted on port 9999

[!WARNING] 
The server ip needs to be a local ip on the same network as the client unless you want to deal with port forwarding the server, which is untested

### password (string) (optional)
- If PBDK is used for handshake_mode then a password string is required for generating a key used to encrypt/decrypt traffic.
     
[!WARNING] 
If no password is provided, the default password of "testPass" will be used, whicch is obviously not secure

## Testing
These are the 2 best methods I've found for testing roxy

### curl
Execute the steps from [Quickstart](#Quickstart)



### firefox
1) Go to firefox settings and set your proxy to the address below, and enable the proxy. Leave all other settings as default
```
127.0.0.1:8888
```

2) open a terminal and run
```bash
python roxy.py client ECC local
```
3) open a 2nd terminal and run
```bash
python roxy.py server ECC local
```

4) Now visit a website and observe the address of the website being printed in the second terminal

[!NOTE] 
The load times in firefox with the proxy tend to be quite slow