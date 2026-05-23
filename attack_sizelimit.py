# בדיקת הגבלות גודל בקשה
# WAF limits: headers 8KB, body 2MB

import socket

server = ("127.0.0.1", 8000)


def try_send(raw_bytes):
    """שולח בקשה ומחזיר status code"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(server)
        s.sendall(raw_bytes)

        buf = b""

        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break
            except Exception as e:
                print("recv warning:", e)
                break

        s.close()

        if not buf:
            return -1, "empty response"
        decoded = buf.decode(errors="replace")
        parts = decoded.split("\r\n")[0].split(" ", 2)

        if len(parts) < 2:
            return -1, decoded

        return int(parts[1]), parts[2] if len(parts) > 2 else ""

    except Exception as e:
        return -1, str(e)


def test_big_header():
    print("test 1 - header 9KB (limit 8KB)")

    padding = "A" * 9000
    req = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8000\r\n"
        "X-Padding: " + padding + "\r\n"
        "\r\n"
    )

    code, msg = try_send(req.encode())


def test_big_body():
    print()
    print("test 2 - body 2.1MB (limit 2MB)")

    big_body = "X" * (2 * 1024 * 1024 + 100000)
    req = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8000\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(big_body)}\r\n"
        "\r\n" + big_body
    )

    code, msg = try_send(req.encode())


def main():
    print(f"Size Limit Test - target {server[0]}:{server[1]}")
    print()
    test_big_header()
    test_big_body()
    print()
    print("check waf events: http://127.0.0.1:8000/waf_events")


if __name__ == "__main__":
    main()
