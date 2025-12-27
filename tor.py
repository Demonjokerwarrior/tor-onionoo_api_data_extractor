#!/usr/bin/env python3
import os
import time
import threading
import subprocess
import sqlite3
import secrets
import requests
import json
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask import Flask, jsonify, request, send_file, render_template

# =====================================================
# CONFIGURATION
# =====================================================
BASE_DIR = os.path.dirname(__file__)
PCAP_DIR = os.path.join(BASE_DIR, "pcaps")
DB_PATH = os.path.join(BASE_DIR, "network.db")
FLOW_WINDOW = 3.0  # seconds for flow grouping
FLOW_RETENTION = 120  # seconds to keep flow history
EMIT_INTERVAL = 0.5  # seconds between socket emits

os.makedirs(PCAP_DIR, exist_ok=True)

# =====================================================
# FLASK APPLICATION
# =====================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
CORS(app)

# =====================================================
# GLOBAL STATE
# =====================================================
PACKETS = deque(maxlen=10000)
PACKET_LOCK = threading.Lock()

FLOWS = {}
FLOW_HISTORY = deque(maxlen=1000)
JA3_STATS = {}
CIRCUITS = {}
TOR_RELAYS = {}
TOR_EXIT_IPS = set()

capture_running = False
capture_processes = []
LAST_EMIT = 0.0

# =====================================================
# DATABASE INITIALIZATION
# =====================================================
def init_database():
    """Initialize SQLite database for packet storage"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER NOT NULL,
            protocol TEXT,
            interface TEXT,
            ja3 TEXT,
            sni TEXT,
            encrypted INTEGER DEFAULT 0,
            tor_related INTEGER DEFAULT 0
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ja3 ON packets(ja3)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time REAL NOT NULL,
            end_time REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            total_bytes INTEGER NOT NULL,
            packet_count INTEGER NOT NULL,
            ja3 TEXT,
            sni TEXT,
            encrypted INTEGER DEFAULT 0,
            tor_circuit_id TEXT
        )
    """)

    conn.commit()
    conn.close()

init_database()

# =====================================================
# DATA MODELS
# =====================================================
@dataclass
class Packet:
    """Packet data model with enhanced fields"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    protocol: str
    interface: str
    ja3: str = ""
    sni: str = ""

    @property
    def encrypted(self):
        """Check if packet is encrypted"""
        return self.protocol.upper() in ("TLS", "HTTPS", "SSL")

    @property
    def tor_related(self):
        """Check if packet involves Tor relays"""
        return (self.src_ip in TOR_RELAYS or
                self.dst_ip in TOR_RELAYS or
                self.src_port in (9050, 9150, 9001, 9030) or
                self.dst_port in (9050, 9150, 9001, 9030))

    def to_dict(self):
        """Convert packet to dictionary for JSON/WebSocket"""
        role = "non_tor"
        if self.src_ip in TOR_RELAYS:
            if "exit" in TOR_RELAYS[self.src_ip]:
                role = "exit_relay"
            elif "entry" in TOR_RELAYS[self.src_ip]:
                role = "entry_guard"
            else:
                role = "middle_relay"
        elif self.dst_ip in TOR_RELAYS:
            if "entry" in TOR_RELAYS[self.dst_ip]:
                role = "entry_guard"

        return {
            "time_formatted": datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3],
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "protocol": self.protocol,
            "interface": self.interface,
            "ja3": self.ja3,
            "sni": self.sni,
            "encrypted": self.encrypted,
            "tor_related": self.tor_related,
            "role": role
        }

    def save_to_db(self):
        """Save packet to database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port, length,
             protocol, interface, ja3, sni, encrypted, tor_related)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.length, self.protocol, self.interface, self.ja3, self.sni,
            int(self.encrypted), int(self.tor_related)
        ))
        conn.commit()
        conn.close()

# =====================================================
# TOR CONSENSUS MANAGEMENT
# =====================================================
def load_tor_consensus():
    """Load Tor network consensus data from Onionoo"""
    global TOR_RELAYS, TOR_EXIT_IPS

    TOR_RELAYS.clear()
    TOR_EXIT_IPS.clear()

    try:
        url = "https://onionoo.torproject.org/details?type=relay&running=true"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()

        for relay in data.get("relays", []):
            if not relay.get("or_addresses"):
                continue

            ip = relay["or_addresses"][0].split(":")[0]
            flags = relay.get("flags", [])

            roles = set()
            if "Guard" in flags:
                roles.add("entry")
            if "Exit" in flags:
                roles.add("exit")
                TOR_EXIT_IPS.add(ip)
            if not roles:
                roles.add("middle")

            TOR_RELAYS[ip] = roles

        print(f"[+] Tor consensus loaded: {len(TOR_RELAYS)} relays, {len(TOR_EXIT_IPS)} exit nodes")

        # Cache consensus to file
        cache_file = os.path.join(BASE_DIR, "tor_consensus_cache.json")
        with open(cache_file, 'w') as f:
            json.dump({
                "relays": {ip: list(roles) for ip, roles in TOR_RELAYS.items()},
                "exits": list(TOR_EXIT_IPS)
            }, f)

    except Exception as e:
        print(f"[!] Failed to load Tor consensus: {e}")
        load_consensus_from_cache()

def load_consensus_from_cache():
    """Load cached consensus if online fetch fails"""
    cache_file = os.path.join(BASE_DIR, "tor_consensus_cache.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
                for ip, roles_list in cached.get('relays', {}).items():
                    TOR_RELAYS[ip] = set(roles_list)
                TOR_EXIT_IPS.update(cached.get('exits', []))
            print(f"[+] Loaded cached consensus: {len(TOR_RELAYS)} relays")
        except Exception as e:
            print(f"[!] Failed to load cached consensus: {e}")

def consensus_refresher():
    """Background thread to periodically refresh Tor consensus"""
    while True:
        load_tor_consensus()
        time.sleep(3600)

# =====================================================
# FLOW ANALYSIS ENGINE
# =====================================================
def flow_id(timestamp):
    """Generate flow ID based on time window"""
    return int(timestamp // FLOW_WINDOW)

def size_signature(sizes, n=5):
    """Create packet size signature for flow fingerprinting"""
    return tuple(sizes[:n])

def process_packet_for_flow(packet):
    flow_window_id = flow_id(packet.timestamp)

    flow_key = (
        packet.src_ip,
        packet.dst_ip,
        packet.ja3,
        packet.sni,
        flow_window_id
    )

    with PACKET_LOCK:
        flow = FLOWS.setdefault(flow_key, {
            "start_time": packet.timestamp,
            "end_time": packet.timestamp,
            "bytes": 0,
            "packets": 0,
            "sizes": [],
            "ja3": packet.ja3,
            "sni": packet.sni,
            "encrypted": packet.encrypted,
            "tor_related": packet.tor_related
        })

        flow["bytes"] += packet.length
        flow["packets"] += 1
        flow["sizes"].append(packet.length)
        flow["end_time"] = packet.timestamp
        flow["fingerprint"] = (packet.ja3, size_signature(flow["sizes"]))

        if packet.ja3:
            JA3_STATS[packet.ja3] = JA3_STATS.get(packet.ja3, 0) + 1

        if flow["packets"] >= 10:
            FLOW_HISTORY.append({
                "key": flow_key,
                "flow": flow.copy()
            })
            save_flow_to_db(flow_key, flow)
            del FLOWS[flow_key]


def save_flow_to_db(flow_key, flow):
    """Save completed flow to database"""
    src_ip, dst_ip, ja3, sni, _ = flow_key

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO flows
        (start_time, end_time, src_ip, dst_ip, total_bytes,
         packet_count, ja3, sni, encrypted, tor_circuit_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        flow["start_time"], flow["end_time"], src_ip, dst_ip,
        flow["bytes"], flow["packets"], ja3, sni,
        int(flow["encrypted"]), None
    ))
    conn.commit()
    conn.close()

# =====================================================
# CORRELATION ENGINE
# =====================================================
def calculate_ja3_rarity(ja3):
    """Calculate rarity score for JA3 fingerprint (0=common, 1=rare)"""
    if not ja3:
        return 0.0

    total_ja3 = sum(JA3_STATS.values())
    if total_ja3 == 0:
        return 1.0

    frequency = JA3_STATS.get(ja3, 0) / total_ja3
    return 1.0 - frequency

def correlate_tor_circuits():
    correlations = []
    seen_pairs = set()

    with PACKET_LOCK:
        for (src1, dst1, ja3_1, sni_1, _), flow1 in FLOWS.items():
            if not ja3_1:
                continue

            if dst1 not in TOR_RELAYS or "entry" not in TOR_RELAYS[dst1]:
                continue

            for (src2, dst2, ja3_2, sni_2, _), flow2 in FLOWS.items():
                if ja3_1 != ja3_2 or sni_1 != sni_2:
                    continue

                if src2 not in TOR_RELAYS or "exit" not in TOR_RELAYS[src2]:
                    continue

                if abs(flow1["start_time"] - flow2["start_time"]) > FLOW_WINDOW * 2:
                    continue

                key = (dst1, src2, ja3_1)
                if key in seen_pairs:
                    continue

                seen_pairs.add(key)
                CIRCUITS.setdefault(key, []).append(flow1["start_time"])

                times = CIRCUITS[key]
                stability = times[-1] - times[0] if len(times) > 1 else 0.0

                correlations.append({
                    "entry_guard": dst1,
                    "exit_relay": src2,
                    "ja3": ja3_1,
                    "sni": sni_1,
                    "rarity": round(calculate_ja3_rarity(ja3_1), 3),
                    "stability": round(stability, 2),
                    "confidence": min(len(times) / 10.0, 1.0),
                    "first_seen": times[0],
                    "last_seen": times[-1],
                    "occurrences": len(times)
                })

    return correlations


def generate_timeline_data():
    """Generate timeline data for circuit activity"""
    timeline = {}
    for _, timestamps in CIRCUITS.items():
        for ts in timestamps:
            bucket = int(ts // 60) * 60
            timeline[bucket] = timeline.get(bucket, 0) + 1

    return [{"time": bucket, "count": count}
            for bucket, count in sorted(timeline.items())]

def calculate_latency_metrics():
    latencies = []

    for (entry, exit_node, _), timestamps in CIRCUITS.items():
        if len(timestamps) >= 2:
            deltas = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            latencies.append({
                "entry": entry,
                "exit": exit_node,
                "avg_latency_ms": round(sum(deltas) / len(deltas) * 1000, 2),
                "min_latency_ms": round(min(deltas) * 1000, 2),
                "max_latency_ms": round(max(deltas) * 1000, 2),
                "samples": len(deltas)
            })

    return latencies

# =====================================================
# PACKET CAPTURE ENGINE
# =====================================================
def capture_loop(interface, bpf_filter):
    """Main packet capture loop for a specific interface"""
    global capture_running, capture_processes, LAST_EMIT

    pcap_filename = f"capture_{interface}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
    pcap_path = os.path.join(PCAP_DIR, pcap_filename)

    cmd = [
        "tshark",
        "-i", interface,
        "-f", bpf_filter,
        "-w", pcap_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.extensions_server_name",
        "-l"
    ]

    process = None

    try:
        print(f"[+] Starting capture on {interface} with filter: {bpf_filter}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        capture_processes.append(process)

        threading.Thread(
            target=read_tshark_stderr,
            args=(process, interface),
            daemon=True
        ).start()

        for line in process.stdout:
            if not capture_running:
                break

            parts = line.strip().split("\t")
            parts += [""] * (9 - len(parts))

            try:
                packet = Packet(
                    timestamp=float(parts[0]) if parts[0] else time.time(),
                    src_ip=parts[1] or "0.0.0.0",
                    dst_ip=parts[2] or "0.0.0.0",
                    src_port=int(parts[3]) if parts[3].isdigit() else 0,
                    dst_port=int(parts[4]) if parts[4].isdigit() else 0,
                    length=int(parts[5]) if parts[5].isdigit() else 0,
                    protocol=parts[6] or "Unknown",
                    interface=interface,
                    ja3=parts[7] or "",
                    sni=parts[8] or ""
                )

                with PACKET_LOCK:
                    PACKETS.append(packet)
                    packet.save_to_db()

                process_packet_for_flow(packet)

                now = time.time()
                if now - LAST_EMIT >= EMIT_INTERVAL:
                    LAST_EMIT = now
                    emit_updates()

            except (ValueError, IndexError):
                continue
            except Exception as e:
                print(f"[!] Error processing packet on {interface}: {e}")
                continue

    except Exception as e:
        print(f"[!] Capture error on {interface}: {e}")

    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        print(f"[+] Capture stopped on {interface}")

def read_tshark_stderr(process, interface):
    """Read and handle tshark stderr output"""
    for line in process.stderr:
        if line.strip():
            print(f"[tshark:{interface}] {line.strip()}")

LAST_CORRELATION_EMIT = 0.0

def emit_updates():
    global LAST_CORRELATION_EMIT

    with PACKET_LOCK:
        recent_packets = list(PACKETS)[-50:]

        total_packets = len(PACKETS)
        total_bytes = sum(p.length for p in PACKETS)
        encrypted_count = sum(1 for p in PACKETS if p.encrypted)
        tor_count = sum(1 for p in PACKETS if p.tor_related)

        packet_data = [p.to_dict() for p in recent_packets]

        stats_data = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "encrypted_packets": encrypted_count,
            "encryption_ratio": round(encrypted_count / max(total_packets, 1), 3),
            "tor_packets": tor_count,
            "tor_ratio": round(tor_count / max(total_packets, 1), 3),
            "active_interfaces": list({p.interface for p in PACKETS}),
            "unique_flows": len(FLOWS),
            "unique_ja3": len(JA3_STATS),
            "detected_circuits": len(CIRCUITS),
            "timestamp": time.time()
        }

    socketio.emit("packet_update", packet_data)
    socketio.emit("stats_update", stats_data)

    now = time.time()
    if now - LAST_CORRELATION_EMIT >= 10:
        LAST_CORRELATION_EMIT = now
        correlations = correlate_tor_circuits()
        if correlations:
            socketio.emit("correlation_update", correlations[:10])

# =====================================================
# FLASK ROUTES
# =====================================================

@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    global capture_running

    if capture_running:
        return jsonify({"status": "error", "message": "Capture already running"})

    capture_running = True
    tor_interface = os.getenv("TOR_IFACE", "any")

    interfaces = {
        "lo": "tcp and (port 9050 or port 9150)",
        tor_interface: "tcp and (port 9001 or port 9030 or port 443)"
    }

    for iface, flt in interfaces.items():
        threading.Thread(
            target=capture_loop,
            args=(iface, flt),
            daemon=True
        ).start()

    return jsonify({
        "status": "success",
        "message": "Capture started",
        "interfaces": list(interfaces.keys())
    })



@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stop all packet capture processes"""
    global capture_running, capture_processes

    capture_running = False

    for process in capture_processes:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

    capture_processes.clear()

    return jsonify({
        "status": "success",
        "message": "Capture stopped",
        "packets_captured": len(PACKETS),
        "flows_detected": len(FLOWS)
    })

@app.route("/api/packets", methods=["GET"])
def get_packets():
    """Get recent packets"""
    limit = request.args.get("limit", 100, type=int)
    with PACKET_LOCK:
        recent = list(PACKETS)[-limit:]
        return jsonify([p.to_dict() for p in recent])

@app.route("/api/packets/filter", methods=["POST"])
def filter_packets():
    """Filter packets by criteria"""
    data = request.json or {}
    src_ip = data.get("src_ip", "")
    dst_ip = data.get("dst_ip", "")
    protocol = data.get("protocol", "")
    tor_only = data.get("tor_only", False)
    encrypted_only = data.get("encrypted_only", False)
    limit = data.get("limit", 100)

    with PACKET_LOCK:
        filtered = []
        for packet in reversed(list(PACKETS)):
            if (not src_ip or packet.src_ip == src_ip) and \
               (not dst_ip or packet.dst_ip == dst_ip) and \
               (not protocol or packet.protocol.lower() == protocol.lower()) and \
               (not tor_only or packet.tor_related) and \
               (not encrypted_only or packet.encrypted):
                filtered.append(packet.to_dict())
                if len(filtered) >= limit:
                    break

        return jsonify(filtered)

@app.route("/api/stats", methods=["GET"])
def get_statistics():
    """Get current statistics"""
    with PACKET_LOCK:
        total_packets = len(PACKETS)
        total_bytes = sum(p.length for p in PACKETS)
        encrypted_count = sum(1 for p in PACKETS if p.encrypted)
        tor_count = sum(1 for p in PACKETS if p.tor_related)

        return jsonify({
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "encrypted_packets": encrypted_count,
            "encryption_ratio": round(encrypted_count / max(total_packets, 1), 3),
            "tor_packets": tor_count,
            "tor_ratio": round(tor_count / max(total_packets, 1), 3),
            "unique_ja3": len(JA3_STATS),
            "active_flows": len(FLOWS),
            "detected_circuits": len(CIRCUITS),
            "tor_relays": len(TOR_RELAYS),
            "exit_nodes": len(TOR_EXIT_IPS),
            "capture_running": capture_running
        })

@app.route("/api/correlations", methods=["GET"])
def get_correlations():
    """Get Tor circuit correlations"""
    limit = request.args.get("limit", 50, type=int)
    correlations = correlate_tor_circuits()
    return jsonify({
        "count": len(correlations),
        "correlations": correlations[:limit]
    })

@app.route("/api/timeline", methods=["GET"])
def get_timeline():
    """Get circuit activity timeline"""
    timeline = generate_timeline_data()
    return jsonify(timeline)

@app.route("/api/latency", methods=["GET"])
def get_latency():
    """Get latency metrics"""
    latencies = calculate_latency_metrics()
    return jsonify({
        "count": len(latencies),
        "latencies": latencies
    })

@app.route("/api/relays", methods=["GET"])
def get_relays():
    """Get Tor relay information"""
    entry_guards = [ip for ip, roles in TOR_RELAYS.items() if "entry" in roles]
    exit_relays = [ip for ip, roles in TOR_RELAYS.items() if "exit" in roles]
    middle_relays = [ip for ip, roles in TOR_RELAYS.items()
                     if "entry" not in roles and "exit" not in roles]

    return jsonify({
        "total_relays": len(TOR_RELAYS),
        "entry_guards": entry_guards,
        "exit_relays": exit_relays,
        "middle_relays": middle_relays,
        "all_relays": list(TOR_RELAYS.keys())
    })

@app.route("/api/report", methods=["GET"])
def generate_report():
    """Generate comprehensive report"""
    with PACKET_LOCK:
        total_packets = len(PACKETS)
        total_bytes = sum(p.length for p in PACKETS)

        protocols = {}
        for p in PACKETS:
            protocols[p.protocol] = protocols.get(p.protocol, 0) + 1

        src_counts = {}
        dst_counts = {}
        for p in PACKETS:
            src_counts[p.src_ip] = src_counts.get(p.src_ip, 0) + 1
            dst_counts[p.dst_ip] = dst_counts.get(p.dst_ip, 0) + 1

        top_sources = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_destinations = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        top_ja3 = sorted(JA3_STATS.items(), key=lambda x: x[1], reverse=True)[:10]

        report = {
            "generated": datetime.utcnow().isoformat(),
            "capture_duration": PACKETS[-1].timestamp - PACKETS[0].timestamp if PACKETS else 0,
            "summary": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "average_packet_size": round(total_bytes / max(total_packets, 1), 2),
                "encryption_ratio": round(sum(1 for p in PACKETS if p.encrypted) / max(total_packets, 1), 3),
                "tor_traffic_ratio": round(sum(1 for p in PACKETS if p.tor_related) / max(total_packets, 1), 3)
            },
            "protocol_distribution": protocols,
            "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
            "top_destinations": [{"ip": ip, "count": count} for ip, count in top_destinations],
            "top_ja3_fingerprints": [{"ja3": ja3, "count": count} for ja3, count in top_ja3],
            "flow_analysis": {
                "active_flows": len(FLOWS),
                "unique_ja3": len(JA3_STATS),
                "flow_history": len(FLOW_HISTORY)
            },
            "tor_analysis": {
                "relays_online": len(TOR_RELAYS),
                "exit_nodes": len(TOR_EXIT_IPS),
                "detected_circuits": len(CIRCUITS),
                "circuit_correlations": correlate_tor_circuits()[:20]
            },
            "timeline": generate_timeline_data(),
            "latency_analysis": calculate_latency_metrics()
        }

        return jsonify(report)

@app.route("/api/pcaps", methods=["GET"])
def list_pcaps():
    """List available PCAP files"""
    if not os.path.exists(PCAP_DIR):
        return jsonify([])

    pcaps = []
    for filename in os.listdir(PCAP_DIR):
        if filename.endswith(".pcap"):
            filepath = os.path.join(PCAP_DIR, filename)
            stat = os.stat(filepath)
            pcaps.append({
                "name": filename,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "download_url": f"/api/pcap/{filename}"
            })

    return jsonify(sorted(pcaps, key=lambda x: x["modified"], reverse=True))

@app.route("/api/pcap/<filename>", methods=["GET"])
def download_pcap(filename):
    """Download a PCAP file"""
    filepath = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404

    return send_file(
        filepath,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.tcpdump.pcap"
    )

@app.route("/api/database/query", methods=["POST"])
def query_database():
    """Execute custom SQL query on packet database"""
    data = request.json or {}
    query = data.get("query", "")
    limit = int(data.get("limit", 100))

    # --- SAFETY CHECK ---
    if not query.strip().lower().startswith("select"):
        return jsonify({"error": "Only SELECT queries allowed"}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Enforce LIMIT if missing
        if "limit" not in query.lower():
            query = f"{query.strip()} LIMIT {limit}"

        cursor.execute(query)
        rows = cursor.fetchall()

        results = [dict(row) for row in rows]

        conn.close()

        return jsonify({
            "success": True,
            "count": len(results),
            "results": results
        })

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 400



@app.route("/api")
def api_index():
    return jsonify({
        "name": "Tor Network Monitor API",
        "version": "1.0.0",
        "endpoints": {
            "capture": {
                "start": "POST /api/capture/start",
                "stop": "POST /api/capture/stop"
            },
            "data": {
                "packets": "GET /api/packets",
                "stats": "GET /api/stats",
                "correlations": "GET /api/correlations",
                "timeline": "GET /api/timeline",
                "latency": "GET /api/latency",
                "relays": "GET /api/relays",
                "report": "GET /api/report"
            },
            "files": {
                "pcaps": "GET /api/pcaps",
                "download": "GET /api/pcap/<filename>"
            }
        }
    })





@app.route("/api/reset", methods=["POST"])
def reset_data():
    """Reset captured data (for testing)"""
    global PACKETS, FLOWS, FLOW_HISTORY, JA3_STATS, CIRCUITS

    with PACKET_LOCK:
        PACKETS.clear()
        FLOWS.clear()
        FLOW_HISTORY.clear()
        JA3_STATS.clear()
        CIRCUITS.clear()

    return jsonify({
        "status": "success",
        # "message": "All data reset"
    })

# =====================================================
# WEBSOCKET HANDLERS
# =====================================================
@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection"""
    print(f"[+] WebSocket client connected: {request.sid}")
    emit("connected", {
        "message": "Connected to Tor Network Monitor",
        "status": "ready",
        "timestamp": time.time()
    })

@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print(f"[+] WebSocket client disconnected: {request.sid}")

@socketio.on("request_stats")
def handle_stats_request():
    """Handle stats request from client"""
    with PACKET_LOCK:
        total_packets = len(PACKETS)
        total_bytes = sum(p.length for p in PACKETS)

        emit("stats_response", {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "capture_running": capture_running,
            "unique_ja3": len(JA3_STATS),
            "tor_relays": len(TOR_RELAYS)
        })

@socketio.on("start_capture")
def handle_start_capture():
    """Handle start capture command via WebSocket"""
    if capture_running:
        emit("capture_status", {"status": "error", "message": "Capture already running"})
        return

    # Start capture via API endpoint
    start_capture()
    emit("capture_status", {"status": "success", "message": "Capture started"})

@socketio.on("stop_capture")
def handle_stop_capture():
    """Handle stop capture command via WebSocket"""
    if not capture_running:
        emit("capture_status", {"status": "error", "message": "Capture not running"})
        return

    stop_capture()
    emit("capture_status", {"status": "success", "message": "Capture stopped"})


@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# =====================================================
# UTILITY FUNCTIONS
# =====================================================
def clean_old_pcaps():
    """Clean old PCAP files (older than 7 days)"""
    while True:
        try:
            now = time.time()
            for filename in os.listdir(PCAP_DIR):
                filepath = os.path.join(PCAP_DIR, filename)
                if os.path.isfile(filepath):
                    if now - os.stat(filepath).st_mtime > 7 * 24 * 3600:
                        os.remove(filepath)
                        print(f"[+] Cleaned old PCAP: {filename}")
        except Exception as e:
            print(f"[!] Error cleaning PCAPs: {e}")
        time.sleep(3600)

# =====================================================
# MAIN ENTRY POINT
# =====================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Tor Network Monitor - Advanced Correlation Engine")
    print("=" * 60)

    print("[+] Loading Tor consensus data...")
    load_tor_consensus()

    threading.Thread(target=consensus_refresher, daemon=True).start()
    threading.Thread(target=clean_old_pcaps, daemon=True).start()

    print("[+] Starting WebSocket server on http://0.0.0.0:5000")
    print("[+] API available at http://localhost:5000")
    print("[+] WebSocket events: packet_update, stats_update, correlation_update")
    print("=" * 60)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True,
        log_output=False
    )
