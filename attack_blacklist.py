# בדיקת IP blacklisting
# שולח בקשות זדוניות כדי לגרום ל-WAF לחסום את ה-IP שלנו
# 3 עבירות = באן ל-5 דקות

import socket
import time

waf_addr = ("127.0.0.1", 8000)

# הבקשות הזדוניות שנשלח
bad_requests = [
    "GET /login?username=' OR 1=1 -- HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n",
    "GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n",
    "GET /download?file=../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n",
    "GET /login?username=' UNION SELECT * FROM users -- HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n",
]

normal_req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n"


def send_request(raw_http):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(waf_addr)
        s.sendall(raw_http.encode())

        resp = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            resp += d
        s.close()

        line = resp.decode(errors="replace").split("\r\n")[0]
        parts = line.split(" ", 2)
        code = int(parts[1])
        msg = parts[2] if len(parts) > 2 else ""
        return code, msg

    except Exception as e:
        return -1, str(e)


def main():
    print("IP Blacklist Test")
    print(f"target: {waf_addr[0]}:{waf_addr[1]}")
    print("3 offenses = banned for 5 min")
    print()

    # שלב 1 - שולח בקשות זדוניות
    print("sending malicious requests...")
    for i, payload in enumerate(bad_requests, 1):
        code, msg = send_request(payload)
        print(f"  attack {i}: HTTP {code} {msg}")
        time.sleep(0.3)

    print()

    # שלב 2 - בודק אם ה-IP נחסם
    print("checking if we got banned...")
    time.sleep(0.5)

    code, msg = send_request(normal_req)
    print(f"  normal request: HTTP {code} {msg}")
    print()

    if code == 403:
        print("IP got blacklisted! even normal requests blocked")
    elif code == 200:
        print("request went through - WAF probably in dry-run mode")
    else:
        print(f"unexpected status {code}")


if __name__ == "__main__":
    main()
