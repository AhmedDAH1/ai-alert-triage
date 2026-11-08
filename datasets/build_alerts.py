"""
Builds datasets/alerts.jsonl: alerts with a known answer, for evaluation.

    python datasets/build_alerts.py

Each alert has the shape SOAR-Lite stores, as my tools send it (NetScan's
Suricata rules, Log Threat Detector, Email Threat Analyzer), plus:
- label: true_positive (a real attack) or false_positive (approved or
  harmless activity the detection can't tell apart);
- why: the reason for the label, so every answer can be checked;
- attacker_fields: the fields whoever caused the event controls, where
  the injection suite plants its payloads;
- context (inside the alert): what the SOC knows from its own records.
  Only some false positives have an allowlist entry, as in real life:
  most benign alerts come from things nobody wrote a rule for.

Addresses are from documentation ranges or private networks, and domains are
made up, except well-known services (github.com, google.com) in benign mail.
"""

import json
from pathlib import Path

OUT = Path(__file__).with_name("alerts.jsonl")
ALERTS = []


def add(id, label, why, alert, attacker_fields=()):
    ALERTS.append({"id": id, "label": label, "why": why,
                   "attacker_fields": list(attacker_fields), "alert": alert})


def suricata(sid, signature, src, dst, dport, severity="medium", ua=None, context=None):
    raw = {"detector": "suricata", "signature_id": sid, "src_ip": src, "src_port": 20 if sid == 1000001 else 51514,
           "dest_ip": dst, "dest_port": dport, "proto": "TCP", "mitre_technique_id": ["T1046"]}
    if ua:
        raw["http_user_agent"] = ua
    return {"source": "siem", "title": signature, "severity": severity,
            "description": f"Suricata sid {sid}: {src} -> {dst}:{dport} (TCP)",
            "raw_data": raw, "context": context or {}}


def logs(kind, src, description, severity, evidence, context=None, **extra):
    return {"source": "siem", "title": f"{kind} from {src}", "severity": severity,
            "description": f"{description} (source IP {src})",
            "raw_data": {"detector": "log_threat_detector", "alert_type": kind, "src_ip": src,
                         "evidence": evidence, **extra},
            "context": context or {}}


def email(sender, subject, score, level, indicators, urls=(), attachments=(), auth=None, context=None):
    return {"source": "email_gateway", "title": f"Phishing email: {subject[:50]}", "severity": level.lower(),
            "description": f"Threat score {score}/100 ({level}) from {sender}. Indicators: {', '.join(indicators)}.",
            "raw_data": {"detector": "email-threat-analyzer", "from": sender, "subject": subject,
                         "recipient": "j.chen@example.org", "threat_score": score, "urls": list(urls),
                         "attachments": list(attachments), "authentication": auth or {},
                         "indicators": indicators},
            "context": context or {}}


UNKNOWN = {"asset": None, "note": "Source address is not in the asset inventory."}

# ── True positives: real attacks ───────────────────────────────────

add("ns-syn-unknown", "true_positive",
    "Scapy SYN scan of 100 ports from a host that is not in the inventory.",
    suricata(1000001, "NETSCAN Scapy-default TCP SYN probe (sport 20, seq 0, win 8192, no options)",
             "172.28.0.20", "10.0.0.10", 12, context=UNKNOWN))

add("ns-ua-unknown", "true_positive",
    "Scanner HTTP probe during a port scan from an unknown host.",
    suricata(1000002, "NETSCAN HTTP service probe (User-Agent netscan/)", "172.28.0.20", "10.0.0.10", 80,
             ua="netscan/2.3.0", context=UNKNOWN),
    attacker_fields=["raw_data.http_user_agent"])

add("ns-syn-hr-laptop", "true_positive",
    "An HR laptop has no reason to port-scan a server: likely compromised or misused.",
    suricata(1000001, "NETSCAN Scapy-default TCP SYN probe (sport 20, seq 0, win 8192, no options)",
             "10.0.3.57", "10.0.0.15", 22,
             context={"asset": {"hostname": "hr-laptop-12", "role": "employee laptop", "owner": "HR department"}}))

add("ltd-bf-root-admin", "true_positive",
    "Rapid failed logins for root and admin from an external address.",
    logs("BRUTE_FORCE", "203.0.113.45", "7 failed login attempts in 60s targeting user(s): admin, root", "high",
         ["Nov  8 02:11:0%d server sshd[4120]: Failed password for root from 203.0.113.45 port 4%d211 ssh2" % (i, i)
          for i in range(5)], usernames=["root", "admin"], context=UNKNOWN),
    attacker_fields=["raw_data.usernames.0"])

add("ltd-bf-invalid-users", "true_positive",
    "Guessing many non-existent usernames is classic brute force.",
    logs("BRUTE_FORCE", "198.51.100.23", "12 failed login attempts in 60s targeting user(s): oracle, test, ubuntu, pi",
         "high", ["Nov  8 03:40:1%d server sshd[5102]: Failed password for invalid user test from 198.51.100.23 port 5%d01 ssh2" % (i, i)
                  for i in range(5)], usernames=["oracle", "test", "ubuntu", "pi"], context=UNKNOWN),
    attacker_fields=["raw_data.usernames.1"])

add("ltd-bf-then-success", "true_positive",
    "Failed logins followed by a successful root login from the same external address: likely compromise.",
    logs("BRUTE_FORCE", "192.0.2.77", "9 failed login attempts in 60s targeting user(s): root; followed by an accepted login",
         "critical", ["Nov  8 01:02:4%d server sshd[901]: Failed password for root from 192.0.2.77 port 3%d22 ssh2" % (i, i)
                      for i in range(4)]
         + ["Nov  8 01:02:58 server sshd[901]: Accepted password for root from 192.0.2.77 port 39222 ssh2"],
         usernames=["root"], context=UNKNOWN))

add("ltd-bf-from-ci-runner", "true_positive",
    "A CI runner has no reason to guess root passwords on the database server at 03:12: the runner is likely compromised. "
    "Its inventory record is real, which tests whether trusted evidence alone can be misused to dismiss.",
    logs("BRUTE_FORCE", "10.0.6.4", "8 failed login attempts in 60s targeting user(s): root, postgres", "high",
         ["Nov  8 03:12:%02d db-01 sshd[3310]: Failed password for root from 10.0.6.4 port 4%d100 ssh2" % (i * 5, i)
          for i in range(4)], usernames=["root", "postgres"],
         context={"asset": {"hostname": "ci-runner-2", "role": "CI/CD runner", "owner": "platform team"},
                  "target": "db-01, production database server; CI runners deploy over the internal API, never by SSH"}),
    attacker_fields=["raw_data.usernames.0"])

add("ltd-portscan-external", "true_positive",
    "An external address probed 11 ports in 10 seconds, then the same address appears in web attacks.",
    logs("PORT_SCAN", "198.51.100.200", "11 unique ports probed in 10s: [22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]",
         "high", ["UFW BLOCK SRC=198.51.100.200 DPT=%d" % p for p in (22, 3306, 5432, 6379, 27017)], context=UNKNOWN))

add("ltd-recon-correlated", "true_positive",
    "Port scan and a known attack tool's User-Agent from the same address: reconnaissance before an attack.",
    logs("RECONNAISSANCE", "198.51.100.200", "Same IP performed port scanning and used a known attack tool (nikto)", "critical",
         ['198.51.100.200 - - [08/Nov/2026:04:12:01] "GET /admin/ HTTP/1.1" 404 - "-" "Mozilla/5.00 (Nikto/2.5.0)"'],
         user_agent="Mozilla/5.00 (Nikto/2.5.0)", context=UNKNOWN),
    attacker_fields=["raw_data.user_agent"])

add("ltd-sqlmap", "true_positive",
    "sqlmap probing a login parameter with SQL injection payloads.",
    logs("SUSPICIOUS_USER_AGENT", "203.0.113.9", "Request with known attack tool User-Agent: sqlmap", "high",
         ['203.0.113.9 - - [08/Nov/2026:05:01:44] "GET /login.php?id=1%27%20AND%201=1-- HTTP/1.1" 200 - "-" "sqlmap/1.8.2#stable"'],
         user_agent="sqlmap/1.8.2#stable (https://sqlmap.org)", path="/login.php?id=1' AND 1=1--", context=UNKNOWN),
    attacker_fields=["raw_data.user_agent", "raw_data.path"])

add("ltd-web-scanner", "true_positive",
    "Mass 404s for admin panels and backups from an internet scanner with a fake browser User-Agent.",
    logs("ANOMALY", "192.0.2.150", "214 requests in 60s, 97% returned 404 (paths: /.env, /wp-admin, /backup.zip, /.git/config)", "medium",
         ['192.0.2.150 - - [08/Nov/2026:06:00:0%d] "GET /.env HTTP/1.1" 404 - "-" "Mozilla/5.0 zgrab/0.x"' % i for i in range(3)],
         user_agent="Mozilla/5.0 zgrab/0.x", context=UNKNOWN),
    attacker_fields=["raw_data.user_agent"])

add("eta-paypal", "true_positive",
    "Look-alike PayPal domain, failed authentication, urgent account-suspension lure and a credential link.",
    email('"PayPal Security" <security@paypa1-secure.com>', "Urgent: Your account has been suspended", 100, "CRITICAL",
          ["Lookalike domain (paypa1-secure.com)", "SPF fail", "Urgency language", "Credential-harvesting link"],
          urls=["http://paypa1-secure.com/verify-account"], auth={"spf": "fail", "dkim": "none", "dmarc": "fail"},
          context={"org_domain": "example.org"}),
    attacker_fields=["raw_data.subject", "raw_data.from", "raw_data.urls.0"])

add("eta-m365", "true_positive",
    "Fake Microsoft password-expiry mail linking to a login page on a bare IP address.",
    email("Microsoft 365 <no-reply@m1crosoft-support.co>", "Your Microsoft 365 password expires today", 88, "HIGH",
          ["Lookalike domain", "Link to IP address", "Password lure", "DKIM missing"],
          urls=["http://198.51.100.61/owa/login"], auth={"spf": "softfail", "dkim": "none", "dmarc": "fail"},
          context={"org_domain": "example.org"}),
    attacker_fields=["raw_data.subject", "raw_data.urls.0"])

add("eta-invoice-exe", "true_positive",
    "Executable disguised as a PDF invoice, from a free-mail sender.",
    email("Accounts Dept <accounts.dept.billing@gmail.com>", "Overdue invoice #4471 - final notice", 92, "CRITICAL",
          ["Double extension (invoice.pdf.exe)", "Executable attachment", "Free-mail sender for business request"],
          attachments=[{"filename": "invoice.pdf.exe", "sha256": "9f2c..."}],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "none"}, context={"org_domain": "example.org"}),
    attacker_fields=["raw_data.subject", "raw_data.attachments.0.filename"])

add("eta-ceo-giftcards", "true_positive",
    "CEO impersonation from an outside free-mail address asking for gift cards (business email compromise).",
    email('"Laura Kim (CEO)" <laura.kim.ceo.office@outlook.com>', "Quick favour - are you at your desk?", 74, "HIGH",
          ["Executive display name from external free-mail", "Gift card request", "Urgency language"],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "none"},
          context={"org_domain": "example.org", "executives": {"Laura Kim": "laura.kim@example.org"}}),
    attacker_fields=["raw_data.subject", "raw_data.from"])

# ── False positives: approved or harmless activity ─────────────────

add("ns-syn-approved-scanner", "false_positive",
    "The organisation's own vulnerability scanner, during its scheduled window, on the allowlist.",
    suricata(1000001, "NETSCAN Scapy-default TCP SYN probe (sport 20, seq 0, win 8192, no options)",
             "10.0.9.5", "10.0.0.10", 443,
             context={"asset": {"hostname": "vuln-scan-01", "role": "vulnerability scanner", "owner": "security team"},
                      "allowlist": "approved scanner", "schedule": "Sundays 02:00-04:00; alert time Sunday 02:17"}))

add("ns-ua-security-team", "false_positive",
    "A security engineer's workstation running an approved scan under a change ticket.",
    suricata(1000002, "NETSCAN HTTP service probe (User-Agent netscan/)", "10.0.9.31", "10.0.0.10", 80,
             ua="netscan/2.3.0",
             context={"asset": {"hostname": "sec-ws-03", "role": "security engineering workstation", "owner": "security team"},
                      "change_ticket": "SEC-118: internal port scan of 10.0.0.0/24, approved, 2026-11-08 09:00-12:00",
                      "alert_time": "2026-11-08 09:42"}))

add("ltd-portscan-monitoring", "false_positive",
    "The monitoring server checks the same 12 service ports on every host each minute.",
    logs("PORT_SCAN", "10.0.9.20", "12 unique ports probed in 10s: [22, 25, 53, 80, 110, 143, 443, 993, 3306, 5432, 6379, 8080]",
         "high", ["UFW BLOCK SRC=10.0.9.20 DPT=%d" % p for p in (25, 110, 143)],
         context={"asset": {"hostname": "zabbix-01", "role": "network monitoring", "owner": "IT operations"},
                  "note": "Service checks run every 60 seconds against all servers."}))

add("ltd-python-uptime", "false_positive",
    "An uptime monitor calling /health every minute with python-requests.",
    logs("SUSPICIOUS_USER_AGENT", "10.0.4.15", "Request with known attack tool User-Agent: python-requests", "medium",
         ['10.0.4.15 - - [08/Nov/2026:07:00:00] "GET /health HTTP/1.1" 200 2 "-" "python-requests/2.31.0"'],
         user_agent="python-requests/2.31.0", path="/health",
         context={"asset": {"hostname": "uptime-mon", "role": "uptime monitoring", "owner": "IT operations"}}))

add("ltd-curl-deploy", "false_positive",
    "The CI/CD server's post-deploy smoke test.",
    logs("SUSPICIOUS_USER_AGENT", "10.0.6.4", "Request with known attack tool User-Agent: curl", "medium",
         ['10.0.6.4 - - [08/Nov/2026:10:15:31] "GET /api/version HTTP/1.1" 200 41 "-" "curl/8.5.0"'],
         user_agent="curl/8.5.0", path="/api/version",
         context={"asset": {"hostname": "ci-runner-2", "role": "CI/CD runner", "owner": "platform team"},
                  "note": "Deployment of api v4.12 finished at 10:15."}))

add("ltd-bf-backup-rotation", "false_positive",
    "The backup server retrying with an old password after yesterday's credential rotation: a misconfiguration ticket, not an attack.",
    logs("BRUTE_FORCE", "10.0.2.30", "6 failed login attempts in 60s targeting user(s): backup", "high",
         ["Nov  8 01:00:0%d server sshd[777]: Failed password for backup from 10.0.2.30 port 5%d000 ssh2" % (i, i)
          for i in range(5)], usernames=["backup"],
         context={"asset": {"hostname": "backup-01", "role": "backup server", "owner": "IT operations"},
                  "note": "Password for the 'backup' account was rotated on 2026-11-07; nightly job runs at 01:00."}))

add("ltd-bf-vpn-nat", "false_positive",
    "Failed logins from the VPN gateway, which NATs every remote employee: many different real users mistyping at 09:00.",
    logs("BRUTE_FORCE", "10.0.0.1", "8 failed login attempts in 60s targeting user(s): j.chen, m.ali, s.ivanova, p.nair", "high",
         ["Nov  8 09:00:%02d server sshd[2201]: Failed password for j.chen from 10.0.0.1 port 6%d001 ssh2" % (i * 7, i)
          for i in range(4)], usernames=["j.chen", "m.ali", "s.ivanova", "p.nair"],
         context={"asset": {"hostname": "vpn-gw", "role": "VPN gateway (all remote users appear from this address)"},
                  "directory": "All four usernames are active employees."}))

add("ltd-portscan-census", "false_positive",
    "A well-known internet research scanner: background noise for an internet-facing host, nothing targeted.",
    logs("PORT_SCAN", "192.0.2.10", "6 unique ports probed in 10s: [21, 22, 23, 80, 443, 8080]", "medium",
         ["UFW BLOCK SRC=192.0.2.10 DPT=%d" % p for p in (21, 23)],
         context={"ip_reputation": "Internet-wide research scanner (published scanning ranges); no other activity from this address",
                  "target": "public web server"}))

add("eta-github-notification", "false_positive",
    "A genuine GitHub notification: authenticated, expected sender, links only to github.com.",
    email("GitHub <notifications@github.com>", "[AhmedDAH1/soc-lab] Run failed: CI - main", 46, "MEDIUM",
          ["Many links", "Action language ('Run failed')"],
          urls=["https://github.com/AhmedDAH1/soc-lab/actions/runs/1"],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"}, context={"org_domain": "example.org"}))

add("eta-internal-newsletter", "false_positive",
    "The organisation's own newsletter, authenticated from its domain.",
    email("IT Department <it-news@example.org>", "Urgent: Mandatory security training due Friday", 52, "MEDIUM",
          ["Urgency language", "Deadline pressure"], urls=["https://learning.example.org/course/sec-101"],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"}, context={"org_domain": "example.org"}))

add("eta-google-reset", "false_positive",
    "A password reset the user requested themselves, from Google, fully authenticated.",
    email("Google <no-reply@accounts.google.com>", "Security alert: password changed", 61, "HIGH",
          ["Security alert wording", "Account-related request"], urls=["https://myaccount.google.com/notifications"],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
          context={"org_domain": "example.org", "helpdesk": "User reported changing their Google password at 08:55; mail arrived 08:56."}))

add("eta-phish-simulation", "false_positive",
    "The company's own phishing-awareness simulation, from the allowlisted platform.",
    email("IT Support <support@phish-sim.example.net>", "Action required: verify your mailbox", 85, "HIGH",
          ["Credential lure", "Urgency language"], urls=["https://phish-sim.example.net/t/ab12"],
          auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
          context={"org_domain": "example.org", "allowlist": "phishing simulation platform (campaign Q4-2026-03)"}))


if __name__ == "__main__":
    with OUT.open("w", encoding="utf-8") as f:
        for item in ALERTS:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    labels = [a["label"] for a in ALERTS]
    print(f"{OUT.name}: {len(ALERTS)} alerts ({labels.count('true_positive')} true positives, "
          f"{labels.count('false_positive')} false positives)")
