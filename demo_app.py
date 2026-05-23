# שרת BookWorm - ספריית ספרים אונליין
# רץ על פורט 5000, ה-WAF מעביר לפה בקשות

import socket
import threading
import sqlite3
import os
import html as html_mod
import urllib.parse
from http_parser import HTTPRequest
import crypto_utils

DEMO_DB = "demo.db"
BOOKS_DIR = os.path.join("www", "books")

def init_demo_db():
    conn = sqlite3.connect(DEMO_DB)
    cursor = conn.cursor()

    # טבלת users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id       INTEGER PRIMARY KEY,
            title    TEXT,
            author   TEXT,
            filename TEXT,
            description TEXT
        )
    """)

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) "
            "VALUES (?, ?, ?, ?)",
            [
                ("admin",     "12345!",   "admin@bookworm.com",  "admin"),
                ("john_doe",  "password1", "john@bookworm.com",   "user"),
                ("sarah_k",   "letmein",   "sarah@bookworm.com",  "user"),
                ("mike_r",    "qwerty99",  "mike@bookworm.com",   "manager"),
                ("test_user", "test123",   "test@bookworm.com",   "user"),
            ]
        )

    cursor.execute("SELECT COUNT(*) FROM books")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO books (title, author, filename, description) "
            "VALUES (?, ?, ?, ?)",
            [
                ("Python Basics",
                 "John Smith",
                 "python_basics.txt",
                 "A beginner-friendly guide to Python programming."),
                ("Web Security 101",
                 "Sarah Johnson",
                 "web_security_101.txt",
                 "Learn about common web vulnerabilities and how to prevent them."),
                ("Database Fundamentals",
                 "Mike Chen",
                 "database_fundamentals.txt",
                 "Introduction to SQL, tables, and database design."),
                ("JavaScript Guide",
                 "Emily Davis",
                 "javascript_guide.txt",
                 "Modern JavaScript from the ground up."),
                ("Network Protocols",
                 "Alex Wilson",
                 "network_protocols.txt",
                 "Understanding TCP/IP, HTTP, and DNS."),
            ]
        )

    conn.commit()
    conn.close()


def build_response(body_text, content_type="text/html; charset=utf-8"):
    body = body_text.encode("utf-8") if isinstance(body_text, str) else body_text
    header = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + str(len(body)) + "\r\n"
        "\r\n"
    )
    return header.encode("utf-8") + body

#הבסיס שיש בכל עמוד העיצוב
SITE_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: #fff8f0; color: #333; }

/* top bar */
.topbar {
  background: #5D4037; color: white;
  padding: 14px 24px; display: flex;
  align-items: center; justify-content: space-between;
}
.topbar .logo { font-size: 20px; font-weight: bold; }
.topbar nav a {
  color: #ffccbc; text-decoration: none;
  margin-left: 18px; font-size: 14px;
}
.topbar nav a:hover { color: white; }

/* main */
.container { max-width: 900px; margin: 24px auto; padding: 0 16px; }

h2 { margin-bottom: 12px; color: #4E342E; }

/* books */
.book-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
.book-card {
  background: white; border: 1px solid #ddd;
  border-radius: 6px; padding: 14px;
}
.book-card h3 { font-size: 15px; margin-bottom: 4px; }
.book-card .author { font-size: 13px; color: #888; margin-bottom: 6px; }
.book-card .desc { font-size: 13px; color: #555; margin-bottom: 8px; }
.book-card a {
  font-size: 13px; color: #E65100;
  text-decoration: none; font-weight: bold;
}
.book-card a:hover { text-decoration: underline; }

/* forms */
.form-box {
  background: white; border: 1px solid #ddd;
  border-radius: 6px; padding: 20px;
  max-width: 400px; margin-top: 12px;
}
.form-box label { display: block; font-size: 13px; margin-bottom: 4px; color: #555; }
.form-box input[type=text],
.form-box input[type=password] {
  width: 100%; padding: 8px 10px;
  border: 1px solid #ccc; border-radius: 4px;
  font-size: 14px; margin-bottom: 12px;
}
.form-box button {
  padding: 8px 20px; background: #5D4037;
  color: white; border: none; border-radius: 4px;
  font-size: 14px; cursor: pointer;
}
.form-box button:hover { background: #4E342E; }

/* tables */
table {
  width: 100%; border-collapse: collapse;
  margin-top: 10px; font-size: 13px;
}
th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
th { background: #EFEBE9; }

/* messages */
.msg-ok { color: #2E7D32; font-weight: bold; margin: 10px 0; }
.msg-err { color: #C62828; font-weight: bold; margin: 10px 0; }

/* file content box */
pre.file-content {
  background: #f5f5f5; border: 1px solid #ddd;
  padding: 12px; border-radius: 4px;
  overflow-x: auto; font-size: 13px;
  margin-top: 8px; max-height: 400px;
  overflow-y: auto;
}

/* search */
.search-bar { display: flex; gap: 8px; margin-bottom: 16px; }
.search-bar input[type=text] {
  flex: 1; padding: 8px 10px;
  border: 1px solid #ccc; border-radius: 4px; font-size: 14px;
}
.search-bar button {
  padding: 8px 16px; background: #E65100;
  color: white; border: none; border-radius: 4px;
  font-size: 14px; cursor: pointer;
}
.search-bar button:hover { background: #BF360C; }

.info-box {
  background: #FFF3E0; border: 1px solid #FFE0B2;
  border-radius: 6px; padding: 12px;
  font-size: 13px; color: #E65100;
  margin-top: 12px;
}

@media (max-width: 600px) { .book-grid { grid-template-columns: 1fr; } }
"""

def page_layout(title, content):
    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        "<title>" + html_mod.escape(title) + " - BookWorm</title>"
        "<style>" + SITE_CSS + "</style>"
        "</head><body>"
        "<div class='topbar'>"
        "  <span class='logo'>BookWorm Online Library</span>"
        "  <nav>"
        "    <a href='/'>Home</a>"
        "    <a href='/login'>Login</a>"
        "    <a href='/search'>Search</a>"
        "    <a href='/download'>Download</a>"
        "  </nav>"
        "</div>"
        "<div class='container'>"
        + content +
        "</div>"
        "</body></html>"
    )


def get_home_page():
    conn = sqlite3.connect(DEMO_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, author, filename, description FROM books")
    books = cursor.fetchall()
    conn.close()

    html = "<h2>Welcome to BookWorm</h2>"
    html += "<p>Browse our collection of free programming books.</p>"
    html += "<div class='book-grid'>"
    for book in books:
        book_id, title, author, filename, desc = book
        html += (
            "<div class='book-card'>"
            "<h3>" + html_mod.escape(title) + "</h3>"
            "<div class='author'>by " + html_mod.escape(author) + "</div>"
            "<div class='desc'>" + html_mod.escape(desc) + "</div>"
            "<a href='/download?file=" + html_mod.escape(filename) + "'>Download</a>"
            "</div>"
        )
    html += "</div>"
    return page_layout("Home", html)


def get_login_form():
    html = (
        "<h2>Login</h2>"
        "<div class='form-box'>"
        "<form method='POST' action='/login'>"
        "  <label>Username</label>"
        "  <input type='text' name='username' placeholder='Enter username'>"
        "  <label>Password</label>"
        "  <input type='password' name='password' placeholder='Enter password'>"
        "  <button type='submit'>Log In</button>"
        "</form>"
        "</div>"
        "<div class='info-box'>"
        "try logging in with username <b>admin</b> and password <b>12345!</b>"
        "</div>"
    )
    return page_layout("Login", html)


def handle_login(username, password):
    # פגיע ל-SQLi בכוונה
    query = (
        "SELECT id, username, password, email, role "
        "FROM users "
        "WHERE username='" + username + "' "
        "AND password='" + password + "'"
    )

    conn = sqlite3.connect(DEMO_DB)
    cursor = conn.cursor()
    rows = []
    error_msg = ""
    try:
        cursor.execute(query)
        rows = cursor.fetchall() #תוצאה - השורות הרלוונטיות
    except Exception as e:
        error_msg = str(e)
    conn.close()

    html = "<h2>Login Result</h2>"

    html += (
        "<p style='font-size:13px;color:#888;'>SQL query that was executed:</p>"
        "<pre class='file-content'>" + html_mod.escape(query) + "</pre>"
    )

    if error_msg:
        html += "<p class='msg-err'>SQL Error: " + html_mod.escape(error_msg) + "</p>"
    elif rows:
        html += "<p class='msg-ok'> Login successful!</p>"
    else:
        html += "<p class='msg-ok'>Login failed &mdash; no matching user.</p>"

    html += "<p style='margin-top:16px;'><a href='/login'>Try again</a></p>"
    return page_layout("Login Result", html)


def get_search_page(query_text):
    html = (
        "<h2>Search Books</h2>"
        "<form class='search-bar' method='GET' action='/search'>"
        "<input type='text' name='q' placeholder='Search by title or author...' "
        "value='" + html_mod.escape(query_text) + "'>"
        "<button type='submit'>Search</button>"
        "</form>"
    )

    if query_text:
        # פגיע ל-XSS בכוונה
        html += "<p>Results for: <b>" + query_text + "</b></p>"

        conn = sqlite3.connect(DEMO_DB)
        cursor = conn.cursor()
        safe_query = "%" + query_text + "%"
        cursor.execute(
            "SELECT id, title, author, filename, description FROM books "
            "WHERE title LIKE ? OR author LIKE ?",
            (safe_query, safe_query)
        )
        books = cursor.fetchall()
        conn.close()

        if books:
            html += "<div class='book-grid'>"
            for book in books:
                book_id, title, author, filename, desc = book
                html += (
                    "<div class='book-card'>"
                    "<h3>" + html_mod.escape(title) + "</h3>"
                    "<div class='author'>by " + html_mod.escape(author) + "</div>"
                    "<div class='desc'>" + html_mod.escape(desc) + "</div>"
                    "<a href='/download?file=" + html_mod.escape(filename) + "'>Download</a>"
                    "</div>"
                )
            html += "</div>"
        else:
            html += "<p style='color:#999;'>No books matched your search.</p>"
    else:
        html += "<p style='color:#999;'>Enter a search term above.</p>"

    return page_layout("Search", html)


def handle_download(filename):
    if not filename:
        # אין file  מציג רשימה
        conn = sqlite3.connect(DEMO_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT title, filename FROM books")
        books = cursor.fetchall()
        conn.close()

        html = "<h2>Download Books</h2>"
        html += "<p>Click a link to view the book content:</p>"
        html += "<ul style='margin-top:10px;'>"
        for title, fname in books:
            html += (
                "<li style='margin:6px 0;'>"
                "<a href='/download?file=" + html_mod.escape(fname) + "'>"
                + html_mod.escape(title) + "</a>"
                " <span style='color:#999;font-size:12px;'>(" + html_mod.escape(fname) + ")</span>"
                "</li>"
            )
        html += "</ul>"
        html += (
            "<div class='info-box'>"
            "Hint: try changing the <code>file=</code> parameter in the URL "
            "to <code>../../secrets.txt</code> to attempt path traversal."
            "</div>"
        )
        return page_layout("Download", html)

    # פגיע ל-path traversal בכוונה
    full_path = os.path.join(BOOKS_DIR, filename)
    resolved = os.path.abspath(full_path)
    allowed_dir = os.path.abspath(BOOKS_DIR)

    html = "<h2>File Viewer</h2>"
    html += "<p><b>Requested:</b> " + html_mod.escape(filename) + "</p>"
    html += "<p><b>Resolved to:</b> " + html_mod.escape(resolved) + "</p>"

    if not resolved.startswith(allowed_dir):
        html += (
            "<p class='msg-err'>"
            "PATH TRAVERSAL: this file is OUTSIDE the books directory!</p>"
        )
    else:
        html += "<p class='msg-ok'>Path is inside the books directory.</p>"

    if os.path.isfile(resolved):
        try:
            with open(resolved, "r", errors="replace") as f:
                content = f.read(4096)
            html += "<p><b>File content:</b></p>"
            html += "<pre class='file-content'>" + html_mod.escape(content) + "</pre>"
        except Exception as e:
            html += "<p class='msg-err'>Error reading file: " + html_mod.escape(str(e)) + "</p>"
    else:
        html += "<p style='color:#999;'>File not found at this path.</p>"

    html += "<p style='margin-top:16px;'><a href='/download'>Back to list</a></p>"
    return page_layout("File Viewer", html)


def handle_route(request, client_socket):
    path = request.path or "/"

    if path == "/":
        client_socket.sendall(build_response(get_home_page()))

    elif path == "/login":
        if request.method == "POST":
            username = request.form.get("username", [""])[0]
            password = request.form.get("password", [""])[0]
            page = handle_login(username, password)
        else:
            page = get_login_form()
        client_socket.sendall(build_response(page))

    elif path == "/search":
        query_text = request.query_params.get("q", [""])[0]
        page = get_search_page(query_text)
        client_socket.sendall(build_response(page))

    elif path == "/download":
        filename = request.query_params.get("file", [""])[0]
        page = handle_download(filename)
        client_socket.sendall(build_response(page))

    else:
        page = page_layout("Not Found", "<h2>404 - Page Not Found</h2>")
        client_socket.sendall(build_response(page))


# אוסף את ה-response במקום לשלוח ישירות
class SecureSocket:
    def __init__(self):
        self.buffer = b""

    def sendall(self, data):
        self.buffer += data


def handle_client(client_socket):
    try:
        aes_key = crypto_utils.perform_server_handshake(client_socket)

        encrypted_request = crypto_utils.recv_msg(client_socket)
        if not encrypted_request:
            return

        request_data = crypto_utils.aes_decrypt(aes_key, encrypted_request)
        request = HTTPRequest(request_data)

        secure_socket = SecureSocket()
        handle_route(request, secure_socket)

        if secure_socket.buffer:
            print(f"sent: {secure_socket.buffer}")
            encrypted_response = crypto_utils.aes_encrypt(aes_key, secure_socket.buffer)
            crypto_utils.send_msg(client_socket, encrypted_response)

    except Exception as e:
        #print("DEBUG handle_client:", request_data[:100])
        print("Error: " + str(e))
    finally:
        client_socket.close()


def main():
    init_demo_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 5000))
    server.listen(5)
    print("BookWorm server running on port 5000")

    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


if __name__ == "__main__":
    main()
