import socket
import re
import threading
from http_parser import HTTPRequest
import urllib.parse
import time
from collections import deque
import sqlite3
import json
import crypto_utils
import waf_dashboard

DB_NAME = "waf_logs.db"
DRY_RUN = True  # True = dry run, False = blocking

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            url TEXT,
            reason TEXT
        )
    """)
    conn.commit()
    conn.close()
#הוספה לטבלה של ההתקפות
def log_attack(ip, url, reason):
    try:
        conn = sqlite3.connect(DB_NAME) #חיבור לטבלת נתונים
        cur = conn.cursor()
        cur.execute("INSERT INTO attack_logs (ip, url, reason) VALUES (?, ?, ?)", (ip, str(url), reason)) #הוספה לטבלה
        conn.commit() #שמירה
        conn.close()
    except Exception as e:
        print(f"[Log Error] {e}")

# RATE_LIMITING
rate_max=20
rate_sec=30

rate_map={} #ip:time_start,count_req
rate_lock = threading.Lock()

#DDOS - מזהה לפי כמות IP-ים שונים בשנייה
max_ips_per_sec=3
ATTACK_COOLDOWN_SEC = 30
conn_history = deque()  # (timestamp, ip)
conn_lock = threading.Lock()
attack_until = 0

verified_ips = {}
verified_lock = threading.Lock()
CHALLENGE_TIMEOUT = 300  # 5 דקות שהוא מאומת

# IP Blacklisting
BLACKLIST_TIME_SEC = 300  # 5 minutes הזמן שמשתמש נחסם אחרי זה הוא משתחרר
MAX_OFFENSES = 3
blacklist_map = {}
blacklist_lock = threading.Lock() # נעילה של המילון

#הוספה של עבירה +בדיקה אם לחסום
def record_suspicious_activity(ip):
    now = time.time()
    with blacklist_lock:
        if ip not in blacklist_map:
            blacklist_map[ip] = [0, 0]
        
        if blacklist_map[ip][1] > now:#בודק אם הוא כבר חסום
            return
            
        blacklist_map[ip][0] += 1 #הוספה של התקפה
        if blacklist_map[ip][0] >= MAX_OFFENSES: #מעל 3נחסם
            blacklist_map[ip][1] = now + BLACKLIST_TIME_SEC #קובע זמן סיום חסימה = עכשיו + 5 דקות
            print(f"[Blacklist] IP {ip} banned for {BLACKLIST_TIME_SEC}s")

#בודק אםip חסום
def is_ip_blacklisted(ip):
    now = time.time()
    with blacklist_lock:
        if ip in blacklist_map:
            banned_until = blacklist_map[ip][1]
            if banned_until > now:
                return True #חסום
            elif banned_until != 0 and banned_until <= now: #אם עבר זמן החסימה
                blacklist_map[ip] = [0, 0] #מאפס
    return False

#'or 1=1;--
SQLI_PATTERNS = [
    r"(?i)\bor\b\s+1\s*=\s*1\b",
    r"(?i)union\s+select",
    r"--",
]
#<script>alert('XSS')</script>
XSS_PATTERNS = [
    r"<\s*script\b",
    r"on\w+\s*=",
    r"javascript\s*:",
    r"<\s*img\b",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2[eE]%2[eE]%2[fF]",
    r"%2[eE]%2[eE]%5[cC]"
]

MAX_HEADER_SIZE = 8192  # 8KB הסטנדרט למנוע dos עומס על השרת והזיכרון
MAX_BODY_SIZE = 2 * 1024 * 1024 #בקשות רגילות 2MB

#מקבלת את כל הביטים ומחברת לבקשת http מלאה (headers+body
def receive_full_request(client_socket):
    buffer = b""

    try:
        while b"\r\n\r\n" not in buffer: # הסימון של סוף ה־HTTP headers
            chunk = client_socket.recv(1024)
            if not chunk:
                return b""
            buffer += chunk
            if len(buffer) > MAX_HEADER_SIZE:
                return b"HEADER_TOO_LARGE"

        headers_part, body_part = buffer.split(b"\r\n\r\n", 1) #למקרה והheaders קצר והגיע גם body בקבלה

        headers_text = headers_part.decode(errors="ignore")
        content_length = 0

        for line in headers_text.split("\r\n"): # עוברים על הheaders
            if line.lower().startswith("content-length"):
                try:
                    content_length = int(line.split(":", 1)[1].strip()) # מוציאים את המספר בלבד
                except ValueError:
                    content_length = 0

        if content_length > MAX_BODY_SIZE:
            return b"BODY_TOO_LARGE"

        while len(body_part) < content_length:
            chunk = client_socket.recv(1024)
            if not chunk:
                return b""
            body_part += chunk
            if len(body_part) > MAX_BODY_SIZE:
                return b"BODY_TOO_LARGE" # בדיקה חוזרת כי יכול להיות שמה שתכתוב בheader לא נכון

        return headers_part + b"\r\n\r\n" + body_part

    except (ConnectionResetError, socket.timeout):
        return b""

#שולחת ללקוח ומוסיפה headers
def send_response(client_socket, body, status="200 OK", content_type="text/html", connection="close", extra_headers=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    header_lines = [
        f"HTTP/1.1 {status}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        f"Connection: {connection}",
    ]
    if extra_headers:
        header_lines.extend(f"{k}: {v}" for k, v in extra_headers.items())
    header = ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8")
    try:
        client_socket.sendall(header + body)
    except Exception:
        pass


def build_response_str(body, status="200 OK", content_type="text/plain", connection="close"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {connection}\r\n"
        "\r\n"
    ).encode("utf-8")
    return header + body


CHALLENGE_HTML = """
    <html>
    <body>
        <h2>Security Check</h2>
        <form action="/waf_challenge" method="GET">
            Solve: 3 + 7 = ?
            <input name="ans">
            <button type="submit">Subsmit</button>
        </form>
    </body>
    </html>
    """


def send_challenge_page(client_socket):
    send_response(client_socket, CHALLENGE_HTML)

def detect_sql_injection(value):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def detect_xss(value):
    if not isinstance(value, str):
        return False
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


def detect_path_traversal(value):
    if not isinstance(value, str):
        return False
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def is_request_suspicious(req):
    candidates = []

    if req.path:
        candidates.append(req.path)
    if req.body:
        candidates.append(req.body)

    for values in req.query_params.values():
        candidates.extend(values)

    for values in req.form.values():
        candidates.extend(values)

    for value in candidates:
        if not isinstance(value, str):
            continue

        decoded_value = urllib.parse.unquote_plus(value) #הופך % לתווים כל הקידודים שאי אפשר לכתוב בurl
        double_decoded = urllib.parse.unquote_plus(decoded_value)#קידוד כפול Double Encodingeגרש=%2527
        normalized_value = double_decoded.lower()

        print(normalized_value)
        if detect_sql_injection(normalized_value) or detect_sql_injection(value):
            return True
        if detect_xss(normalized_value) or detect_xss(value):
            return True
        if detect_path_traversal(normalized_value) or detect_path_traversal(value):
            return True

    return False


def detect_rate_limiting(ip):
    now = time.time()

    with rate_lock:
        if ip not in rate_map:
            rate_map[ip] = [now, 1]
            return False

        win_start, count = rate_map[ip]

        # אם החלון נגמר אז מאפסים
        if now - win_start >= rate_sec:
            rate_map[ip] = [now, 1]
            return False

        # עדיין בתוך החלון
        if count >= rate_max:
            return True

        # מותר עוד בקשה
        rate_map[ip][1] = count + 1
        return False

def is_under_ddos_attack(now):
    return now < attack_until


def update_attack_state(now, ip):
    global attack_until

    with conn_lock:
        conn_history.append((now, ip))

        # מוחקים חיבורים ישנים יותר משנייה
        while conn_history and now - conn_history[0][0] > 1:
            conn_history.popleft()

        # סופרים כמה IP-ים שונים התחברו בשנייה האחרונה
        unique_ips = set()
        for t, addr in conn_history:
            unique_ips.add(addr)

        # DDoS רק אם יש הרבה IP-ים שונים, לא רק IP אחד ששולח הרבה
        if len(unique_ips) > max_ips_per_sec:
            if now >= attack_until:
                print(f"[DDoS] Under Attack! {len(unique_ips)} unique IPs/sec")
            attack_until = now + ATTACK_COOLDOWN_SEC

def is_verified(ip):
    now = time.time()
    with verified_lock:
        if ip in verified_ips:
            if verified_ips[ip] > now:
                return True
            else:
                del verified_ips[ip]
    return False

def set_verified(ip):
    with verified_lock:
        expiry_timestamp = time.time() + CHALLENGE_TIMEOUT
        verified_ips[ip] = expiry_timestamp
        print(f"[Challenge] Verified IP: {ip} for {CHALLENGE_TIMEOUT} sec")

def send_error_response(client_socket, status, body):
    send_response(client_socket, body, status=status, content_type="text/plain")

def get_events(since_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row #גישה לפי שם
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, ip, url, reason "
            "FROM attack_logs WHERE id > ? "
            "ORDER BY id DESC LIMIT 100",
            (since_id,),
        )#מביא 100 אירועים מסודר מחדש לישן שגדולים מid הנתון
        rows = [dict(row) for row in cursor.fetchall()] #ממיר כל שורה למילון
        conn.close()
        return rows #רשימה של מילונים כל האירועים
    except Exception:
        return []

#כותרות שמכריחות את הדפדפן לא לשמור במטמון את הדשבורד/פעולות הבקרה
#בלי זה דפדפנים (Chrome) שומרים 302 ופעולות חוזרות לא מגיעות לשרת
NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}

#content_type="text/html
#מעביר את המידע כhtml
def send_html_response(client_socket, html, connection="close"):
    send_response(
        client_socket,
        html,
        content_type="text/html; charset=utf-8",
        connection=connection,
        extra_headers=NO_CACHE_HEADERS,
    )

#הופך את המידע לפורמט json
# מוסיף header שאומר שמקבלים json ולא html
def send_json_response(client_socket, data, connection="close"):
    send_response(client_socket, json.dumps(data), content_type="application/json", connection=connection)

#מפנה את הדפדפן לכתובת אחרת אחרי שהמשתמש לחץ על כפתור פעולה
#status=303 See Other - הסטטוס הנכון ל-form submit→result page (לא נשמר במטמון)
def send_redirect(client_socket, location, connection="close"):
    header_lines = [
        "HTTP/1.1 303 See Other",
        f"Location: {location}",
        "Content-Length: 0",
        f"Connection: {connection}",
        "Cache-Control: no-store, no-cache, must-revalidate",
        "Pragma: no-cache",
    ]
    header = ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8")
    try:
        client_socket.sendall(header)
    except Exception:
        pass

#מחזיר את רשימת הIPים החסומים (כולל זמן שנשאר)
def get_blacklist_snapshot():
    now = time.time()
    blocked = []
    with blacklist_lock:
        for blocked_ip, info in blacklist_map.items():
            banned_until = info[1]
            if banned_until > now:
                blocked.append({"ip": blocked_ip, "expires_in": int(banned_until - now)})
    return blocked

def current_mode():
    return "dry_run" if DRY_RUN else "blocking"

def handle_ddos_challenge(req, ip, client_socket, detected_attacks):
    if is_under_ddos_attack(time.time()) and not is_verified(ip):
        log_attack(ip, getattr(req, "path", "-"), "DDoS Challenge Triggered")
        detected_attacks.append("DDoS Challenge Triggered")

        if not DRY_RUN:
            if req.path and req.path.startswith("/waf_challenge"):
                answer = req.query_params.get("ans", [""])[0]

                if answer == "10":
                    set_verified(ip)
                    send_response(client_socket, "<h2>Verified. You can return to the site.</h2>")
                    return True
                else:
                    send_challenge_page(client_socket)
                    return True
            else:
                send_challenge_page(client_socket)
                return True

    return False

#עושה את כל הבדיקות
def run_waf_checks(req, ip, client_socket, detected_attacks):
    now = time.time()

    # DDoS
    if handle_ddos_challenge(req, ip, client_socket, detected_attacks):
        return "break"

    # Rate limit
    if detect_rate_limiting(ip):
        record_suspicious_activity(ip)
        log_attack(ip, getattr(req, "path", "-"), "Rate Limiting")
        detected_attacks.append("Rate Limiting")
        return "continue"

    # Suspicious payload
    if is_request_suspicious(req):
        record_suspicious_activity(ip)
        log_attack(ip, getattr(req, "path", "-"), "Suspicious Payload")
        detected_attacks.append("Suspicious Payload")

        if not DRY_RUN:
            return "break"

    return None

def apply_waf_policy(detected_attacks, client_socket):
    # block or pass through
    if detected_attacks and not DRY_RUN:
        if "IP Blacklisted" in detected_attacks or "Suspicious Payload" in detected_attacks:
            send_error_response(client_socket, "403 Forbidden", "Blocked by WAF")
            return "break"

        elif "Rate Limiting" in detected_attacks:
            send_response(
                client_socket,
                "Too Many Requests",
                status="429 Too Many Requests",
                content_type="text/plain",
                connection="keep-alive"
            )
            return "continue"

        # elif "DDoS Challenge Triggered" not in detected_attacks:
        #     send_error_response(client_socket, "400 Bad Request", "Bad Request")
        #     return "break"

    return None

def add_waf_debug_header(response, detected_attacks):
    if not DRY_RUN or not detected_attacks:
        return response

    attacks_str = ", ".join(detected_attacks).encode("utf-8")
    header = b"X-WAF-Detected: " + attacks_str + b"\r\n"

    if b"\r\n" in response:
        parts = response.split(b"\r\n", 1)
        return parts[0] + b"\r\n" + header + parts[1]

    return response + header

#בונה את ה־HTML של הדשבורד דרך waf_dashboard.draw_dashboard ושולח ללקוח
# לוקחים את הנתונים העדכניים מהWAF
def handle_dashboard(request_data, client_socket):
    events = get_events(since_id=0)
    html = waf_dashboard.draw_dashboard(
        mode=current_mode(),
        blacklist=get_blacklist_snapshot(),
        events=events,
    )
    send_html_response(client_socket, html, connection="keep-alive")
    return True

WAF_CONTROL_SECRET = "supersecretwafkey"
DASHBOARD_PATH = "/waf_events"

#מבצע פעולת בקרה (toggle/add/remove) ואז מפנה את הדפדפן בחזרה לדשבורד
def handle_waf_control(request_data, client_socket):
    global DRY_RUN

    first_line = request_data.split(b"\r\n")[0].decode()
    url_part = first_line.split(" ")[1] #/waf_control?action=...&secret=...
    query_string = url_part.split("?", 1)[1] if "?" in url_part else ""
    params = urllib.parse.parse_qs(query_string)

    #בדיקת סיסמא משותפת - אם חסר/שגוי לא מבצעים כלום
    if params.get("secret", [""])[0] != WAF_CONTROL_SECRET:
        send_error_response(client_socket, "403 Forbidden", "Forbidden")
        return True

    action = params.get("action", [""])[0]

    if action == "toggle_mode": #מצב התראה <-> חסימה
        DRY_RUN = not DRY_RUN

    elif action == "add_blacklist": #חסימה ידנית
        target_ip = params.get("ip", [""])[0]
        if target_ip:
            with blacklist_lock:
                blacklist_map[target_ip] = [MAX_OFFENSES, time.time() + 999999]

    elif action == "remove_blacklist": #הסרת חסימה
        target_ip = params.get("ip", [""])[0]
        if target_ip:
            with blacklist_lock:
                if target_ip in blacklist_map:
                    del blacklist_map[target_ip]

    send_redirect(client_socket, DASHBOARD_PATH, connection="keep-alive")
    return True

def handle_client(client_socket, client_addr):
    try:
        ip = client_addr[0]
        client_socket.settimeout(30)  # timeout לחיבורי keep-alive

        while True:
            detected_attacks = [] #רשימה שאוספת את כל סוגי ההתקפות שזוהו בבקשה הנוכחית
            if is_ip_blacklisted(ip):
                log_attack(ip, "-", "IP Blacklisted") #/waf_events
                detected_attacks.append("IP Blacklisted") #מסמן שהבקשה הנוכחית היא בעייתית לשימוש בapply_waf_policy
            request_data = receive_full_request(client_socket) #מקבל את ההודעה הפונקציה מחזירה בבייטים
            if not request_data:
                return #עובר לחיבור הבא הלקוח התנתק

            # waf control api - הסיסמא נבדקת בתוך handle_waf_control
            if request_data.startswith(b"GET /waf_control"):
                handle_waf_control(request_data, client_socket)
                continue

            # dashboard page (server-rendered HTML, ראה waf_dashboard.py)
            if request_data.startswith(b"GET /waf_events"):
                handle_dashboard(request_data, client_socket)
                continue

            if request_data == b"HEADER_TOO_LARGE":
                log_attack(ip, "-", "Header Too Large")
                send_error_response(client_socket, "431 Request Header Fields Too Large", "Header Too Large")
                return
            if request_data == b"BODY_TOO_LARGE":
                log_attack(ip, "-", "Body Too Large")
                send_error_response(client_socket, "413 Payload Too Large", "Body Too Large")
                return

            req = HTTPRequest(request_data)#יוצר אובייקט
            if req.error: #req.error = "Malformed request line"
                path = getattr(req, "path", "-")#אם אין path אז מייצר "-"
                if not path: #כשהוא ריק
                    path = "-"
                log_attack(ip, path, f"Bad Request: {req.error}")
                detected_attacks.append(f"Bad Request: {req.error}")

            # DDoS / rate limit / security checks
            action = run_waf_checks(req, ip, client_socket, detected_attacks)
            # if action == "break":
            #     break
            # elif action == "continue":
            #     continue

            # block or pass through
            action = apply_waf_policy(detected_attacks, client_socket)
            if action == "break":
                break
            elif action == "continue":
                continue

            # forward to backend
            backend_response = forward_to_backend(request_data) #מקבל תשובה מהשרת את מה שצריך
            # אם יש מתקפה ולא חוסמים הופסת header
            backend_response = add_waf_debug_header(backend_response, detected_attacks)
            print(f"send to client: {backend_response}")
            client_socket.sendall(backend_response) #שולח ללקוח תשובה

            # check if client wants to close
            conn = req.headers.get("connection", "")
            if conn.lower() == "close":
                break

    finally:
        client_socket.close()

def forward_to_backend(raw_data):
    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        backend.connect(("127.0.0.1", 5000))
        
        # TLS handshake עם הbackend
        aes_key = crypto_utils.perform_client_handshake(backend)
        
        # הצפנה ושליחה
        print (f"send bookserver:{raw_data}")
        encrypted_req = crypto_utils.aes_encrypt(aes_key, raw_data)
        #print(encrypted_req)
        crypto_utils.send_msg(backend, encrypted_req)

        # קבלה ופענוח
        encrypted_resp = crypto_utils.recv_msg(backend)
        if encrypted_resp:
            return crypto_utils.aes_decrypt(aes_key, encrypted_resp)
        return b""

    except Exception as e:
        #print("DEBUG forward:", raw_data[:80])
        print(f"Backend Connection/TLS Error: {e}")
        return build_response_str("Backend SSL/TLS Handshake Error or Backend Down", status="502 Bad Gateway")

    finally:
        try:
            backend.close()
        except Exception:
            pass


def main():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8000))
    server.listen(100)

    print("WAF running on 8000")

    while True:
        client_socket, client_addr = server.accept()
        now = time.time()

        # ddos tracking
        update_attack_state(now, client_addr[0])

        thread = threading.Thread(target=handle_client,args=(client_socket, client_addr))
        thread.start()


if __name__ == "__main__":
    main()
