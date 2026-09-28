+++
title = "KnightCTF - Networking Forensics Series"
date = 2026-09-28T09:00:00+07:00
draft = false
tags = ["KnightCTF", "Networking", "Forensics", "PCAP", "Wireshark", "tshark"]
categories = ["Writeups"]
summary = "PCAP analysis writeup cho KnightCTF Networking/Forensics: scan ports, gateway vendor, WordPress exploitation, reverse shell và DB credential leak."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hero-cyber-city.png"
  alt = "Cyber city networking forensics cover"
+++

Category: **Networking / Forensics**  
Artifacts: `pcap1.pcapng`, `pcap2.pcapng`, `pcap3.pcapng`

---

## Summary

This writeup covers the full solution path for the networking/forensics challenges solved from the provided packet captures:

1. **Reconnaissance** — determine how many open ports were discovered during scanning (pcap1)
2. **Gateway Identification** — determine the default gateway vendor (pcap1)
3. **Exploitation** — identify targeted web application and obtain version + username (pcap2)
4. **Vulnerability Exploitation** — identify exploited vulnerable WordPress plugin and version (pcap2)
5. **Post-Exploitation** — identify HTTP payload delivery port and reverse shell port (pcap3)
6. **Database Credentials Theft** — extract database username and password exposed in post-exploitation traffic (pcap3)

---

## Environment / Tooling

Recommended tooling used for all PCAP analysis:

- **Wireshark** (filters, follow streams, reassembly)
- **tshark** (CLI extraction)
- Optional:
  - **Python** for bulk parsing / automation
  - **scapy** for custom packet processing

---

## 1) Reconnaissance – Open Ports Found (pcap1)

**Goal:** Determine how many ports were found open on the target during the scan.

### Method

A classic TCP SYN scan identifies open ports by observing a **SYN → SYN/ACK** response.

- Scanner sends: `SYN`
- If port open, target responds: `SYN,ACK`
- Scanner completes or resets: `RST` / `ACK`

### Wireshark filter

To view candidate scan traffic:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

To identify open ports on the target, filter for SYN/ACKs from the target:

```wireshark
ip.src == 192.168.1.102 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

### Findings

- **Scanner IP:** `192.168.1.104`
- **Target IP:** `192.168.1.102`

Count unique ports where the target responded with SYN/ACK:

- TCP/22
- TCP/80

**Answer:** `2`  
**Flag:** `KCTF{2}`

---

## 2) Gateway Identification – Default Gateway Vendor (pcap1)

**Goal:** Identify the vendor of the device acting as the default gateway.

### Method

Default gateway vendor can be derived from:

1. **ARP discovery** (IP ↔ MAC)
2. Vendor from MAC address OUI

### Wireshark filter

```wireshark
arp
```

Identify ARP who-has / is-at for the gateway:

- Gateway IP usually: `192.168.1.1`

### Findings

- **Gateway IP:** `192.168.1.1`
- **Gateway MAC:** `88:bd:09:38:d7:a0`
- OUI: `88:BD:09` → **Netis**

**Flag:** `KCTF{Netis}`

---

## 3) Exploitation – Application Version + Username (pcap2)

**Goal:** Determine the attacked application and extract the version + username from the capture.

### Method

1. Identify web application paths
2. Extract username from `POST` login request
3. Extract version from application HTML / generator / fingerprint endpoints

### Step A — Identify application

Search for common CMS indicators:

```wireshark
http.request.uri contains "wp-"
```

or

```wireshark
http.request.uri contains "wordpress"
```

### Findings

Multiple requests confirm:

- `/wordpress/`
- `/wordpress/wp-login.php`

Targeted application: **WordPress**

### Step B — Extract username

Look for login POST:

```wireshark
http.request.method == "POST"
```

Then inspect the form body in the HTTP stream (Wireshark: **Follow → HTTP Stream**).

Observed POST parameters:

- `log=kadmin_user`

Username: `kadmin_user`

### Step C — Extract WordPress version

Reassemble the response (often gzip). Extract generator/meta or other fingerprinting artifact indicating:

- WordPress **6.9**

**Flag:** `KCTF{6.9_kadmin_user}`

---

## 4) Vulnerability Exploitation – Plugin + Version (pcap2)

**Goal:** Identify the exploited plugin and the exact version.

### Method

Attackers commonly enumerate plugin versions by fetching:

- `wp-content/plugins/<plugin>/readme.txt`

Search for plugin readme requests.

### Wireshark filter

```wireshark
http.request.uri contains "/wp-content/plugins/"
```

### Findings

Observed:

- `GET /wordpress/wp-content/plugins/social-warfare/readme.txt`

Within the response:

- Plugin: **Social Warfare**
- **Stable tag:** `3.5.2`

Challenge expects underscores in flag formatting:

**Flag:** `KCTF{social_warfare_3.5.2}`

---

## 5) Post-Exploitation – Payload HTTP Port + Reverse Shell Port (pcap3)

**Goal:** Identify:
- HTTP port used to deliver initial payload
- Port used for reverse shell connection

---

## A) HTTP Payload Port

### Method

Search for HTTP traffic running on non-standard ports.

### Wireshark filter

```wireshark
http
```

If Wireshark does not automatically decode due to port mismatch:

- Right click TCP stream → **Decode As…** → HTTP

### Findings

Victim requesting payload from attacker:

- `192.168.1.102:40676  ->  192.168.1.104:8767`
- `GET /payload.txt?...`
- Response resembles Python SimpleHTTP server.

HTTP delivery port: `8767`

---

## B) Reverse Shell Port

### Method

Look for long-lived TCP session with interactive plaintext.

Search for keywords:

- `bash`
- `www-data`
- `whoami`

### Wireshark filter

```wireshark
tcp contains "bash" || tcp contains "www-data"
```

### Findings

Interactive session:

- `192.168.1.102:39582  <->  192.168.1.104:9576`

 Reverse shell port: `9576`

**Flag:** `KCTF{8767_9576}`

---

## 6) Database Credentials Theft (pcap3)

**Goal:** Extract DB credentials exfiltrated from victim.

### Method

In WordPress compromise scenarios, DB credentials are frequently obtained from:

- `wp-config.php`

Search for:

- `DB_USER`
- `DB_PASSWORD`
- `define('DB_...')`

### Wireshark filter examples

```wireshark
tcp contains "DB_PASSWORD" || tcp contains "DB_USER"
```

Or follow the reverse shell stream and observe file reads.

### Findings

Exposed database credentials:

- Username: `wpuser`
- Password: `wp@user123`

 **Flag:** `KCTF{wpuser_wp@user123}`

---

## Final Flags

- Recon open ports: `KCTF{2}`
- Gateway vendor: `KCTF{Netis}`
- Exploitation (version + username): `KCTF{6.9_kadmin_user}`
- Vulnerable plugin: `KCTF{social_warfare_3.5.2}`
- Post exploitation ports: `KCTF{8767_9576}`
- DB creds: `KCTF{wpuser_wp@user123}`

---
