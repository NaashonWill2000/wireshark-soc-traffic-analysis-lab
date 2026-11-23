# Wireshark Network Traffic Analysis & SOC Investigation Lab

## Project Overview

This project demonstrates hands-on network traffic analysis and security investigation techniques using Wireshark.

The lab focuses on examining real network packet captures, interpreting communication protocols, and documenting findings using investigative methods relevant to Security Operations Center (SOC) analysts.

Through this project, I analyzed TCP connection establishment, investigated DNS resolution behavior, examined TLS 1.3 communication, and evaluated network traffic for potential security indicators.

The investigations emphasize understanding normal network behavior, identifying anomalies, and distinguishing expected protocol activity from events that may warrant additional security investigation.

## Project Objectives

The primary objectives of this lab are to:

- Analyze TCP three-way handshakes and interpret TCP flags, sequence numbers, and acknowledgment numbers.
- Investigate DNS resolution, including A, AAAA, and CNAME records.
- Examine NXDOMAIN responses and understand their relevance to security monitoring.
- Analyze TLS 1.3 handshake messages, cipher suites, and encrypted communication.
- Investigate TCP retransmissions and connection behavior.
- Apply Wireshark display filters to isolate relevant network traffic.
- Document packet-level observations and findings in structured investigation reports.
- Develop practical network analysis skills applicable to entry-level SOC Analyst and cybersecurity roles.

## Tools & Technologies

| Tool / Technology | Purpose |
|---|---|
| Wireshark | Packet capture inspection and network traffic analysis |
| TCP/IP | Analysis of network connections and transport-layer communication |
| DNS | Domain resolution and DNS response analysis |
| TLS 1.3 | Analysis of encrypted communication and handshake negotiation |
| Windows | Lab operating system |
| Visual Studio Code | Investigation documentation and Markdown editing |
| GitHub | Version control and cybersecurity portfolio documentation |

## Investigations & Technical Findings

This project includes documented network traffic investigations demonstrating practical packet analysis, protocol interpretation, and security investigation techniques.

### 1. TCP Three-Way Handshake Investigation

**Investigation Report:** [TCP Handshake Analysis](investigations/tcp-handshake-analysis.md)

Analyzed TCP connection establishment between a client workstation and a remote server communicating over TCP port 443.

**Key Findings:**
- Identified the SYN, SYN-ACK, and ACK packets involved in establishing the TCP connection.
- Examined TCP flags, relative sequence numbers, and acknowledgment numbers.
- Verified successful TCP connection establishment using packet-level evidence.
- Documented the handshake sequence and supporting Wireshark screenshots.

### 2. DNS Traffic Analysis & NXDOMAIN Investigation

**Investigation Report:** [DNS Investigation](investigations/dns-investigation.md)

Investigated DNS resolution behavior by examining A and AAAA queries for an intentionally nonexistent domain.

**Key Findings:**
- Identified DNS queries and their corresponding responses.
- Correlated DNS transactions using matching transaction IDs.
- Analyzed NXDOMAIN response codes and DNS protocol flags.
- Distinguished expected DNS resolution failures from potential security indicators.
- Documented packet-level evidence and supporting Wireshark screenshots.

### Additional Investigations

The following topics were examined during the lab and are planned for further documentation:

- TCP retransmissions and acknowledgment behavior.
- TCP connection termination and capture limitations.

These investigations will be linked here as their reports are completed.

### 3. TLS 1.3 Handshake Investigation

**Investigation Report:** [TLS 1.3 Handshake Analysis](investigations/tls-handshake-analysis.md)

Analyzed TLS 1.3 handshake negotiation between a client workstation and a remote server communicating over TCP port 443.

**Key Findings:**
- Identified the initial Client Hello, Hello Retry Request, second Client Hello, and Server Hello.
- Examined the client's supported TLS versions and cryptographic key exchange groups.
- Investigated why the server requested a new `secp384r1` key share.
- Verified the negotiated TLS 1.3 cipher suite, `TLS_AES_256_GCM_SHA384`.
- Correlated handshake messages across multiple packets using Wireshark.
- Documented packet-level evidence with four supporting screenshots.