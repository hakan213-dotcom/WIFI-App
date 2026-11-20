
from flask import Flask, request, redirect, render_template_string, flash
import sqlite3
import subprocess
import re
import ipaddress
import os
import platform
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hotspot_manager.db")
HOTSPOT_SUBNET = os.environ.get(
    "HOTSPOT_SUBNET", "192.168.137.0/24"
)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET", "local-dashboard-change-this"
)

# Database
def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    con.execute("""
        CREATE TABLE IF NOT EXISTS policies(
            mac TEXT PRIMARY KEY,
            label TEXT DEFAULT '',
            policy TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            details TEXT,
            created_at TEXT
        )
    """)

    con.commit()
    return con


def log_activity(action, details):
    with connect_db() as con:
        con.execute(
            "INSERT INTO activity(action,details,created_at) VALUES(?,?,?)",
            (action, details,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )


# MAC validation
def normalize_mac(value):
    value = value.strip().upper().replace("-", ":")

    if not re.fullmatch(
        r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", value
    ):
        raise ValueError("Invalid MAC address")

    return value


# Device scanner
def scan_neighbors():

    if platform.system() != "Windows":
        return []

    network = ipaddress.ip_network(
        HOTSPOT_SUBNET, strict=False
    )

    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            errors="ignore",
            timeout=5
        )
    except Exception:
        return []

    found = {}

    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([0-9a-fA-F-]{17})\s+(dynamic|static)",
        re.I
    )

    for line in output.splitlines():

        match = pattern.search(line)

        if not match:
            continue

        try:
            ip = ipaddress.ip_address(match.group(1))

            if ip not in network:
                continue

            mac = normalize_mac(match.group(2))
            found[mac] = str(ip)

        except ValueError:
            continue

    return [
        {"ip": ip, "mac": mac}
        for mac, ip in found.items()
    ]


# Dashboard
@app.route("/")
def dashboard():

    devices = scan_neighbors()

    with connect_db() as con:
        policies = con.execute(
            "SELECT * FROM policies ORDER BY updated_at DESC"
        ).fetchall()

        logs = con.execute(
            "SELECT * FROM activity ORDER BY id DESC LIMIT 12"
        ).fetchall()

    policy_map = {
        p["mac"]: p["policy"] for p in policies
    }

    for device in devices:
        device["policy"] = policy_map.get(
            device["mac"], "none"
        )

    return render_template_string(
        HTML,
        devices=devices,
        policies=policies,
        logs=logs,
        subnet=HOTSPOT_SUBNET,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        allow_count=sum(p["policy"] == "allow" for p in policies),
        block_count=sum(p["policy"] == "block" for p in policies)
    )


# Refresh
@app.post("/scan")
def refresh_scan():

    count = len(scan_neighbors())

    log_activity(
        "REFRESH",
        f"ARP scan found {count} entries"
    )

    flash(f"Scan selesai: {count} entri ARP.")
    return redirect("/")


# Whitelist / Blacklist
@app.post("/policy")
def save_policy():

    try:
        mac = normalize_mac(request.form.get("mac", ""))
        policy = request.form.get("policy", "")
        label = request.form.get("label", "").strip()[:80]

        if policy not in ("allow", "block"):
            raise ValueError("Invalid policy")

        with connect_db() as con:
            con.execute("""
                INSERT INTO policies(
                    mac,label,policy,updated_at
                )
                VALUES(?,?,?,?)
                ON CONFLICT(mac)
                DO UPDATE SET
                    label=excluded.label,
                    policy=excluded.policy,
                    updated_at=excluded.updated_at
            """, (
                mac,
                label,
                policy,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

        log_activity(
            "POLICY",
            f"{mac} set to {policy}"
        )

        flash(
            f"{mac} saved. Policy is recorded only, "
            "not enforced by Windows hotspot."
        )

    except ValueError as error:
        flash(str(error))

    return redirect("/")


# Remove policy
@app.post("/remove")
def remove_policy():

    try:
        mac = normalize_mac(request.form.get("mac", ""))

        with connect_db() as con:
            con.execute(
                "DELETE FROM policies WHERE mac=?",
                (mac,)
            )

        log_activity("REMOVE", f"Removed {mac}")
        flash("Policy removed.")

    except ValueError as error:
        flash(str(error))

    return redirect("/")


# Open Windows hotspot settings
@app.route("/open-hotspot-settings")
def open_hotspot_settings():

    if platform.system() != "Windows":
        flash("Windows only.")
        return redirect("/")

    try:
        os.startfile(
            "ms-settings:network-mobilehotspot"
        )

        log_activity(
            "OPEN SETTINGS",
            "Opened Mobile Hotspot Settings"
        )

        flash(
            "Windows Hotspot Settings opened. "
            "Change SSID/password manually."
        )

    except OSError as error:
        flash(str(error))

    return redirect("/")


if __name__ == "__main__":

    connect_db().close()

    print("Hotspot Device Manager V2")
    print("Open http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
xxxxx
