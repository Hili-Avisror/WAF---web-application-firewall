# בדיקת rate limiting

import socket

HOST = "127.0.0.1"
PORT = 8000
NUM_REQUESTS = 30

def main():
    print("Rate Limit Test")
    print("sending", NUM_REQUESTS, "requests...")
    print()

    for i in range(1, NUM_REQUESTS + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HOST, PORT))
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n")

            resp = b""
            while True:
                part = s.recv(1024)
                if not part:
                    break
                resp += part
            s.close()
        except:
            print()



if __name__ == "__main__":
    main()
