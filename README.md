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

### 4. TCP Retransmission & Duplicate Selective Acknowledgment Investigation

Conducted a packet-level investigation of TCP retransmission behavior, cumulative acknowledgments, and Duplicate Selective Acknowledgment (D-SACK) using Wireshark.

**Key Technical Findings:**

- Identified 1776 bytes of original TCP payload.
- Identified 1460 bytes of overlapping TCP sequence-number ranges.
- Correlated original and retransmitted TCP segments.
- Verified cumulative acknowledgment of transmitted data.
- Analyzed D-SACK evidence confirming duplicate data delivery.
- Examined retransmission timing and Wireshark TCP analysis flags.
- Distinguished TCP reliability mechanisms from potential security incidents.
- Documented investigation limitations and evidence-based conclusions.

**Security Assessment:** The observed packet sequence was consistent with TCP reliability mechanisms. No direct evidence of malicious activity was identified, and the underlying cause of the retransmission could not be conclusively determined.

**Investigation Report:** [TCP Retransmission Analysis](investigations/tcp-retransmission-analysis.md)

### 5. TCP Connection Termination and Capture Limitations Investigation

**Investigation Focus:** TCP session lifecycle analysis, connection termination behavior, and packet capture visibility limitations.

**Key Technical Findings:**

- Isolated bidirectional TCP communication using stream-based display filters.
- Investigated TCP FIN and RST flags to identify connection termination activity.
- Confirmed that no FIN or RST packets were observed within TCP stream 3.
- Analyzed the final observed TCP acknowledgment, including sequence numbers, acknowledgment numbers, and conversation completeness.
- Calculated a remaining observation window of approximately 15.14 seconds.
- Evaluated packet capture limitations and classified the connection termination status as inconclusive.
- Distinguished confirmed technical evidence from unsupported assumptions.

**Skills Demonstrated:**

- TCP session lifecycle analysis
- TCP flag and header analysis
- Network traffic filtering
- Network event timeline reconstruction
- Packet capture visibility assessment
- Evidence-based security analysis
- Technical investigation and reporting

**Full Investigation Report:** [TCP Connection Termination and Capture Limitations Investigation](investigations/tcp-connection-termination-analysis.md)