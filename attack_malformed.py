# בדיקת בקשות HTTP שבורות
# ה-WAF אמור לזהות ולחסום עם 400

import socket

WAF = ("127.0.0.1", 8000)

# (שם הבדיקה, הdata לשלוח)
tests = [
    ("garbage data",                b"asjkdfhaskjdfh\r\n\r\n"),
    ("invalid method",              b"BLAH / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n"),
    ("missing HTTP version",        b"GET /\r\nHost: 127.0.0.1:8000\r\n\r\n"),
    ("bad HTTP version",            b"GET / HTTP/9.9\r\nHost: 127.0.0.1:8000\r\n\r\n"),
    ("no Host header",              b"GET / HTTP/1.1\r\n\r\n"),
    ("empty request line",          b"\r\nHost: 127.0.0.1:8000\r\n\r\n"),
    ("missing blank line at end",   b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000"),
]


def send_broken_request(data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(WAF)
        s.sendall(data)

        buf = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
        s.close()

        if not buf:
            return 0, "no response"

        line1 = buf.split(b"\r\n")[0].decode()
        p = line1.split(" ", 2)
        return int(p[1]) if len(p) >= 2 else 0, p[2] if len(p) > 2 else ""

    except Exception as e:
        return -1, str(e)


def main():
    print("Malformed Request Test")
    print()

    for i, (name, data) in enumerate(tests, 1):
        code, msg = send_broken_request(data)
        print(f"{code}: {msg}")

if __name__ == "__main__":
    main()
