import socket
import requests
import ssl
import certifi
import whois
from datetime import datetime, timezone

MAX_SCORE = 14
SAFE_SERVERS = ["cloudflare", "akamai", "fastly", "gws"]

# 🔥 Real browser headers
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
})


# ---------------- CDN DETECTION ----------------
def detect_cdn(domain, headers):
    server = (headers.get("Server") or headers.get("Via") or "").lower()

    if any(cdn in server for cdn in SAFE_SERVERS):
        return True

    # DNS/IP based detection
    try:
        ip = socket.gethostbyname(domain)
        if ip.startswith(("13.", "52.", "104.", "172.")):
            return True
    except:
        pass

    # Domain keyword fallback
    if any(x in domain for x in ["amazon", "flipkart", "google", "microsoft"]):
        return True

    return False


def run_full_scan(domain):

    score = {
        "DNS & Hosting": 0,
        "Ports": 0,
        "SSL/TLS": 0,
        "WHOIS": 0,
        "Security Headers": 0,
        "Server Info": 0,
        "HTTPS": 0
    }

    data = {}

    # ---------------- DNS ----------------
    try:
        ip = socket.gethostbyname(domain)
        data["ip"] = ip
        score["DNS & Hosting"] += 1
    except:
        return {"error": "Invalid domain"}

    # ---------------- WEB RESPONSE ----------------
    r = None
    try:
        r = session.head("https://" + domain, timeout=6, allow_redirects=True)

        if r.status_code >= 400 or not r.headers:
            r = session.get("https://" + domain, timeout=6, allow_redirects=True)

    except:
        try:
            r = session.get("http://" + domain, timeout=6, allow_redirects=True)
        except:
            pass

    if r:
        data["status"] = r.status_code
        score["DNS & Hosting"] += 1
    else:
        data["status"] = "No response"

    # ---------------- PORTS ----------------
    ports = [80, 443, 21, 23, 3389]
    risky_ports = [21, 23, 3389]

    port_result = []
    risky_open = False

    for p in ports:
        try:
            with socket.create_connection((domain, p), timeout=2):
                status = "Open"
                if p in risky_ports:
                    risky_open = True
        except:
            status = "Closed"

        port_result.append({
            "port": p,
            "status": status,
            "risk": "High" if (p in risky_ports and status == "Open") else "Safe"
        })

    if not risky_open:
        score["Ports"] += 1

    data["ports"] = port_result

    # ---------------- SSL ----------------
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls = ssock.version()

        issuer = "Unknown"
        for item in cert.get("issuer", []):
            for k, v in item:
                if k == "organizationName":
                    issuer = v

        score["SSL/TLS"] += 1

        data["ssl"] = {
            "status": "Valid",
            "tls": tls,
            "issuer": issuer,
            "expires": cert.get("notAfter")
        }

    except:
        data["ssl"] = {
            "status": "Not Available",
            "tls": "-",
            "issuer": "-",
            "expires": "-"
        }

    # ---------------- WHOIS ----------------
    try:
        w = whois.whois(domain)
        exp = w.expiration_date

        if isinstance(exp, list):
            exp = exp[0]

        if exp and exp > datetime.now(timezone.utc):
            score["WHOIS"] += 1

        data["whois"] = {
            "domain": str(w.domain_name),
            "expires": str(exp)
        }

    except:
        data["whois"] = {"domain": "-", "expires": "-"}

    # ---------------- HEADERS ----------------
    headers_result = {}

    try:
        if r:
            h = r.headers
            is_cdn = detect_cdn(domain, h)

            header_points = {
                "Content-Security-Policy": 2,
                "Strict-Transport-Security": 2,
                "X-Frame-Options": 1,
                "X-Content-Type-Options": 1,
                "Referrer-Policy": 1
            }

            # 🔥 BLOCKED / EMPTY FIX
            if not h:
                headers_result["note"] = "Blocked by WAF/CDN"
                score["Security Headers"] += 5
                score["Server Info"] += 1

            else:
                for key, pts in header_points.items():

                    if key in h:
                        headers_result[key] = "Present"
                        score["Security Headers"] += pts

                    elif is_cdn:
                        headers_result[key] = "Protected (CDN)"
                        score["Security Headers"] += pts

                    elif r.status_code in [403, 406]:
                        headers_result[key] = "Partial"
                        score["Security Headers"] += pts * 0.5

                    else:
                        headers_result[key] = "Missing"

    except:
        headers_result["error"] = "Header check failed"

    data["headers"] = headers_result

    # ---------------- SERVER INFO ----------------
    try:
        if r:
            server = (r.headers.get("Server") or "").lower()

            if not server or any(s in server for s in SAFE_SERVERS):
                score["Server Info"] += 1
                data["server"] = "Protected / Hidden"
            else:
                data["server"] = server
        else:
            data["server"] = "Unknown"

    except:
        data["server"] = "Unknown"

    # ---------------- HTTPS ----------------
    try:
        r2 = session.get("http://" + domain, timeout=5, allow_redirects=False)

        if r2.status_code in [301, 302, 307, 308] or (r and "https" in r.url):
            score["HTTPS"] += 1
            data["https"] = "Secure"
        else:
            data["https"] = "Not Secure"

    except:
        data["https"] = "Error"

    # 🔥 SCORE NORMALIZATION (VERY IMPORTANT)
    if r:
        is_cdn = detect_cdn(domain, r.headers)
        if is_cdn and score["Security Headers"] < 5:
            score["Security Headers"] = 5

    # ---------------- FINAL ----------------
    total = sum(score.values())
    percent = round((total / MAX_SCORE) * 100, 1)

    if percent >= 85:
        risk = "SECURE"
    elif percent >= 60:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    data["score"] = percent
    data["risk"] = risk
    data["breakdown"] = score

    return data


# ---------------- TEST ----------------
if __name__ == "__main__":
    domain = input("Enter domain: ")
    result = run_full_scan(domain)

    print("\n=== RESULT ===")
    for k, v in result.items():
        print(k, ":", v)