# סימולציית DDoS - הצפה ממספר כתובות IP
# צריך להריץ עם sudo בשביל ה-IP-ים המזויפים הרשאות מנהל

import socket
import time
import threading
import os
import sys

TARGET = ("127.0.0.1", 8000)
NUM_ATTACKERS = 10
REQS_EACH = 5
BODY_SIZE = 100000  # 100KB לכל בקשה

print_lock = threading.Lock()
stats = {"ok": 0, "challenged": 0, "errors": 0}

fake_ips = [f"127.0.0.{i}" for i in range(2, 2 + NUM_ATTACKERS)]


def setup_fake_ips():
    for ip in fake_ips:
        ret = os.system(f"sudo ifconfig lo0 alias {ip} up 2>/dev/null")
        if ret != 0:
            print("failed")
            return False
    print(f"IPs ready: {fake_ips[0]} to {fake_ips[-1]}")
    return True


def cleanup_fake_ips():
    for ip in fake_ips:
        os.system(f"sudo ifconfig lo0 -alias {ip} 2>/dev/null")


def flood_from_ip(src_ip):
    for n in range(REQS_EACH):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.bind((src_ip, 0)) #לצאת מהמחשב עם ip אחר
            s.connect(TARGET)

            body = "A" * BODY_SIZE
            http_req = (
                "POST / HTTP/1.1\r\n"
                f"Host: {TARGET[0]}:{TARGET[1]}\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            s.sendall(http_req.encode())

            data = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            s.close()
            #מה קורה בכל בקשה
            text = data.decode(errors="replace").lower()
            with print_lock:
                if "challenge" in text or "security check" in text:
                    stats["challenged"] += 1
                    print(f"  {src_ip} #{n+1}: CHALLENGE")
                else:
                    stats["ok"] += 1
                    print(f"  {src_ip} #{n+1}: OK")

        except Exception as e:
            with print_lock:
                stats["errors"] += 1
                print(f"  {src_ip} #{n+1}: ERROR - {e}")


def main():
    if not setup_fake_ips():
        sys.exit(1)

    total = NUM_ATTACKERS * REQS_EACH
    print(f"DDoS Flood - {NUM_ATTACKERS} attackers, {REQS_EACH} reqs each")
    print(f"payload size: {BODY_SIZE // 1000}KB, total: {total} connections")
    threads = []
    t0 = time.time()

    for ip in fake_ips:
        t = threading.Thread(target=flood_from_ip, args=(ip,))
        threads.append(t)
        t.start()
        time.sleep(0.02)

    for t in threads:
        t.join()

    print(f"  OK: {stats['ok']}")
    print(f"  Challenged: {stats['challenged']}")
    print(f"  Errors: {stats['errors']}")
    if stats["challenged"] > 0:
        print("DDoS detection worked!")
    else:
        print("no challenges - maybe WAF is in dry-run?")

    cleanup_fake_ips()


if __name__ == "__main__":
    main()
