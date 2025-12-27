
# Tor Network Monitor – Advanced Correlation Engine

## Overview

**Tor Network Monitor** is an advanced **Linux-based traffic monitoring and analysis system** designed for **Tor middle relay environments**.
It captures **encrypted network metadata**, performs **flow analysis**, **JA3 fingerprinting**, **Tor relay role classification**, and exposes data through a **REST API + WebSocket dashboard**.

This project is **privacy-compliant** and does **not decrypt traffic** or identify users.

---

## Key Features

* Tor **middle relay traffic monitoring**
* Encrypted traffic metadata analysis
* JA3 TLS fingerprint extraction
* Flow-based traffic aggregation
* Entry–Middle–Exit correlation heuristics
* Timeline & latency analysis
* SQLite-backed persistent storage
* REST API + WebSocket live updates
* PCAP capture and download
* Web-based dashboard (Flask + Socket.IO)

---

## Architecture

```
┌──────────────┐
│ Network NIC  │
└──────┬───────┘
       │
   tshark (CLI)
       │
┌──────▼─────────────────────────────┐
│ Python Capture & Analysis Engine    │
│ • Packet parsing                    │
│ • Flow aggregation                  │
│ • JA3 analysis                      │
│ • Tor relay role detection          │
└──────┬─────────────────────────────┘
       │
┌──────▼───────────┐
│ SQLite Database  │
└──────┬───────────┘
       │
┌──────▼─────────────────────┐
│ Flask REST API + WebSocket  │
└──────┬─────────────────────┘
       │
┌──────▼───────────┐
│ Web Dashboard    │
└──────────────────┘
```

---

## Requirements

### Operating System

* Linux (Ubuntu / Debian recommended)

### System Packages

```bash
sudo apt update
sudo apt install -y tor tshark python3 python3-pip
```

### Python Dependencies

```bash
pip install flask flask-socketio flask-cors requests
```

### Permissions

`tshark` requires root or capture permissions:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
```

Or run the application using `sudo`.

---

## Directory Structure

```
project/
├── app.py                     # Main application
├── network.db                 # SQLite database (auto-created)
├── pcaps/                     # Captured PCAP files
├── templates/
│   └── dashboard.html         # Web dashboard
├── tor_consensus_cache.json   # Cached Tor relay data
└── README.md
```

---

## Configuration

### Environment Variables

| Variable    | Description                       | Default |
| ----------- | --------------------------------- | ------- |
| `TOR_IFACE` | Network interface for Tor traffic | `any`   |

Example:

```bash
export TOR_IFACE=wlan0
```

---

## Running the Application

```bash
sudo python3 app.py
```

The server starts on:

* **Dashboard:** [http://localhost:5000](http://localhost:5000)
* **API Base:** [http://localhost:5000/api](http://localhost:5000/api)

---

## API Endpoints

### Capture Control

| Endpoint             | Method | Description           |
| -------------------- | ------ | --------------------- |
| `/api/capture/start` | POST   | Start traffic capture |
| `/api/capture/stop`  | POST   | Stop capture          |

---

### Data APIs

| Endpoint            | Description              |
| ------------------- | ------------------------ |
| `/api/packets`      | Recent packet metadata   |
| `/api/stats`        | Live statistics          |
| `/api/correlations` | Tor circuit correlations |
| `/api/timeline`     | Activity timeline        |
| `/api/latency`      | Latency metrics          |
| `/api/relays`       | Tor relay roles          |
| `/api/report`       | Full analytical report   |

---

### PCAP Management

| Endpoint           | Description         |
| ------------------ | ------------------- |
| `/api/pcaps`       | List captured PCAPs |
| `/api/pcap/<file>` | Download PCAP       |

---

## WebSocket Events

### Emitted Events

* `packet_update`
* `stats_update`
* `correlation_update`

### Client Commands

* `start_capture`
* `stop_capture`
* `request_stats`

---

## Database Schema

### `packets` Table

Stores packet-level metadata:

* Timestamp
* Source/Destination IP
* Ports
* Length
* Protocol
* JA3 fingerprint
* Encryption flag
* Tor-related flag

### `flows` Table

Stores aggregated flow data:

* Start/End time
* Byte count
* Packet count
* JA3/SNI
* Encryption status

---

## Tor Compliance & Ethics

This system:

* **Does NOT decrypt traffic**
* **Does NOT log user identities**
* **Does NOT attempt deanonymization**
* **Analyzes metadata only**

Designed strictly for:

* Academic research
* Network diagnostics
* Relay performance monitoring
* Security education

---

## Known Limitations

* Cannot identify Tor users
* Cannot see destination websites
* Cannot decrypt payloads
* Correlation is heuristic, not attribution

These are **intentional Tor design properties**.

---

## Future Enhancements

* PDF/CSV report export
* Grafana integration
* Advanced flow visualization
* Historical trend analytics
* Alerting engine

---

## Disclaimer

This project is intended for **ethical, legal, and academic use only**.
Operating Tor relays and monitoring traffic must comply with local laws and Tor Project policies.

---

## Author

**Project:** Tor Network Monitor – Advanced Correlation Engine
**Purpose:** Academic / Research / Security Analysis

---

If you want, I can also:

* Generate a **PDF report automatically from `/api/report`**
* Write a **deployment guide**
* Create a **dashboard UI**
* Simplify this into a **single-file demo version**

Just tell me what you need next.
