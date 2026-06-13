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
