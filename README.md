# Custom Network Intrusion Detection System (NIDS)

## What is this?
A custom-built packet sniffer and intrusion detection engine written entirely in pure Python. It intercepts live network traffic at the system level and mathematically unpacks the packets to detect cyberattacks in real-time.

## Why I built it
Instead of using pre-built tools like Wireshark or high-level libraries, I wanted to understand network architecture from first principles. I built this to interact directly with the Operating System's networking stack and decode raw byte streams to truly understand how data moves across a network.

## How it works under the hood
* **Raw Sockets:** Bypasses standard OS routing to capture raw Ethernet frames directly from the Network Interface Card (NIC).
* **Protocol Decoding:** Uses bitwise operations to mathematically unpack Layer 2 (Ethernet), Layer 3 (IPv4), and Layer 4 (TCP/ICMP) headers from raw hexadecimal data.
* **Threat Detection Engine:** Tracks connection states in memory to identify anomalous behavior. It can successfully detect automated Port Scans (like Nmap) and trigger alerts in under a second.

## How to run it
1. This tool requires a Linux environment (or WSL) to access raw sockets.
2. Run the engine: `sudo python3 sniffer.py`
3. To test the detection alarm, run an Nmap scan against the machine in a separate terminal: `nmap localhost`

## System Architecture Diagram

```mermaid
flowchart TD
    %% Styling
    classDef capture fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef decode fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    classDef threat fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef alert fill:#ffebee,stroke:#d32f2f,stroke-width:2px;

    %% Nodes
    Net((Live Network Traffic)) --> Socket[Raw Socket \n socket, struct, time]:::capture
    
    Socket -->|Raw Hex Bytes| Eth[Ethernet Layer Parser \n Extracts MAC Addresses]:::decode
    Eth -->|Layer 2 Payload| IP[IPv4 Layer Parser \n Extracts Source/Dest IPs]:::decode
    
    IP -->|Protocol 1| ICMP[ICMP Parser]:::decode
    IP -->|Protocol 6| TCP[TCP Parser \n Extracts Ports]:::decode
    
    TCP --> Engine{Threat Detection Engine \n Memory State Tracker}:::threat
    Engine -->|Logs IP & Port History| Rule{Scan Rule \n > 5 ports in < 10s?}:::threat
    
    Rule -- YES --> Trigger[Terminal Output \n CRITICAL SECURITY ALERT]:::alert
    Rule -- NO --> Pass[Passively Log to Terminal]
    ICMP --> Pass