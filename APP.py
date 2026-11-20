
from flask import Flask, request, redirect, render_template_string
import subprocess
import sqlite3
import re
import ipaddress
from datetime import datetime

app = Flask(__name__)
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "hotspot.db")
HOTSPOT_SUBNET = "192.168.137.0/24"

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Hotspot Device Manager</title>
<style>
body {
    background:#101827;
    color:white;
    font-family:Arial;
    padding:25px;
}
.container {
    max-width:1100px;
    margin:auto;
}
.card {
    background:#1c293b;
    padding:20px;
    border-radius:12px;
    margin-bottom:20px;
}
h1 { color:#60a5fa; }
table {
    width:100%;
    border-collapse:collapse;
}
th,td {
    padding:13px;
    border-bottom:1px solid #39475a;
    text-align:left;
}
button {
    padding:9px 12px;
    border:0;
    border-radius:6px;
    cursor:pointer;
    color:white;
}
.allow {background:#16a34a;}
.block {background:#dc2626;}
.remove {background:#475569;}
.refresh {background:#2563eb;}
input {
    padding:10px;
    border-radius:5px;
    border:0;
    margin:5px;
}
.allowed {color:#4ade80;}
.blocked {color:#f87171;}
.unknown {color:#facc15;}
.notice {
    background:#423719;
    padding:12px;
    border-radius:8px;
    line-height:1.5;
}
</style>
</head>
<body>
<div class="container">

<h1>HOTSPOT DEVICE MANAGER</h1>
<p>Windows Mobile Hotspot Administration</p>

<div class="notice">
Monitoring menggunakan Windows ARP cache.
Blacklist dan whitelist disimpan sebagai daftar kebijakan,
belum memutus atau mengizinkan koneksi secara langsung.
</div>

<div class="card">
<h2>Device Monitoring</h2>

<form action="/scan" method="post">
<button class="refresh">Refresh Devices</button>
</form>

<p>Total perangkat terdeteksi: {{ devices|length }}</p>

<table>
<tr>
<th>IP Address</th>
<th>MAC Address</th>
<th>Policy</th>
<th>Action</th>
</tr>

{% for d in devices %}
<tr>
<td>{{d.ip}}</td>
<td>{{d.mac}}</td>
<td>
{% if d.policy == 'allow' %}
<span class="allowed">WHITELIST</span>
{% elif d.policy == 'block' %}
<span class="blocked">BLACKLIST</span>
{% else %}
<span class="unknown">UNLISTED</span>
{% endif %}
</td>
<td>
<form action="/policy" method="post">
<input type="hidden" name="mac" value="{{d.mac}}">
<button class="allow" name="policy" value="allow">
Whitelist
</button>
<button class="block" name="policy" value="block">
Blacklist
</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Add Device Manually</h2>

<form action="/policy" method="post">
<input name="mac" placeholder="MAC Address" required>
<select name="policy">
<option value="allow">Whitelist</option>
<option value="block">Blacklist</option>
</select>
<button class="refresh">Save</button>
</form>
</div>

<div class="card">
<h2>Saved Policies</h2>
<table>
<tr>
<th>MAC Address</th>
<th>Policy</th>
<th>Action</th>
</tr>
{% for p in policies %}
<tr>
<td>{{p[0]}}</td>
<td>{{p[1]}}</td>
<td>
<form action="/remove" method="post">
<input type="hidden" name="mac" value="{{p[0]}}">
<button class="remove">Remove</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>

<p>Last updated: {{now}}</p>
</div>
</body>
</html>
"""

def database():
    os.makedirs(BASE_DIR, exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        mac TEXT PRIMARY KEY,
        policy TEXT NOT NULL
    )
    """)
    con.commit()
    return con


def normalize_mac(mac):
    mac = mac.strip().upper().replace("-", ":")
    if not re.fullmatch(
        r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac
    ):
        raise ValueError("Invalid MAC address")
    return mac


def get_devices():
    devices = {}

    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            errors="ignore",
            timeout=5
        )

        network = ipaddress.ip_network(
            HOTSPOT_SUBNET, strict=False
        )

        for line in output.splitlines():
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"([0-9a-fA-F-]{17})\s+(dynamic|static)",
                line,
                re.I
            )

            if match:
                ip = match.group(1)
                mac = normalize_mac(match.group(2))

                if ipaddress.ip_address(ip) in network:
                    devices[mac] = ip

    except Exception as error:
        print("Scan error:", error)

    return devices


def get_policies():
    con = database()
    rows = con.execute(
        "SELECT mac, policy FROM policies"
    ).fetchall()
    con.close()
    return dict(rows)


@app.route("/")
def dashboard():

    devices = get_devices()
    policies = get_policies()

    device_list = []

    for mac, ip in devices.items():
        device_list.append({
            "ip": ip,
            "mac": mac,
            "policy": policies.get(mac, "unknown")
        })

    return render_template_string(
        HTML,
        devices=device_list,
        policies=[
            (mac, policy)
            for mac, policy in policies.items()
        ],
        now=datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    )


@app.route("/scan", methods=["POST"])
def scan():
    return redirect("/")


@app.route("/policy", methods=["POST"])
def policy():

    try:
        mac = normalize_mac(request.form["mac"])
        selected = request.form["policy"]

        if selected not in ["allow", "block"]:
            return "Invalid policy", 400

        con = database()

        con.execute("""
        INSERT INTO policies(mac, policy)
        VALUES (?, ?)
        ON CONFLICT(mac)
        DO UPDATE SET policy=excluded.policy
        """, (mac, selected))

        con.commit()
        con.close()

    except ValueError as error:
        return str(error), 400

    return redirect("/")


@app.route("/remove", methods=["POST"])
def remove():

    mac = normalize_mac(request.form["mac"])

    con = database()
    con.execute(
        "DELETE FROM policies WHERE mac=?",
        (mac,)
    )
    con.commit()
    con.close()

    return redirect("/")


if __name__ == "__main__":
    database()

    print("Hotspot Device Manager Started")
    print("Open: http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=8080,
        debug=False
    )
/hakan
