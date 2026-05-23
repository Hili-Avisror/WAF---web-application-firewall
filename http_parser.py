import urllib.parse
import json

class HTTPRequest:
    def __init__(self, raw_data):
        self.raw = raw_data
        self.method = None
        self.path = None
        self.version = None
        self.headers = {}
        self.body = ""
        self.query_params = {}
        self.form = {}
        self.json = None
        self.error = None

        self.parse()

    def parse(self):
        try:
            text = self.raw.decode(errors="ignore")

            if "\r\n\r\n" not in text:
                self.error = "Invalid HTTP Format"
                return

            header_part, _, body_part = text.partition("\r\n\r\n")
            self.body = body_part

            lines = header_part.split("\r\n")
            if not lines:
                self.error = "Empty Request"
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) != 3:
                self.error = "Malformed Request Line"
                return

            self.method, full_path, self.version = parts

            allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
            if self.method not in allowed_methods:
                self.error = "Invalid Method"
                return

            if self.version not in ["HTTP/1.0", "HTTP/1.1"]:
                self.error = "Invalid HTTP Version"
                return

            # פירוק path + query
            parsed_url = urllib.parse.urlparse(full_path)#url לרשימה
            print(parsed_url)
            self.path = parsed_url.path
            self.query_params = urllib.parse.parse_qs(parsed_url.query) #פרמטרים למילון

            # headers
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    self.headers[key.strip().lower()] = value.strip()

            if len(self.headers) > 50:
                self.error = "Too Many Headers"
                return

            if self.version == "HTTP/1.1" and "host" not in self.headers:
                self.error = "Missing Host Header"
                return

            # parse body לפי Content-Type
            content_type = self.headers.get("content-type", "").lower()
            if self.body:
                self.parse_body(content_type)

        except Exception as e:
            self.error = "Parsing Error"

    def parse_body(self, content_type):
        try:
            # form data
            if "application/x-www-form-urlencoded" in content_type:
                self.form = urllib.parse.parse_qs(self.body)
                print(self.form)
                return

            # json
            if "application/json" in content_type and self.body:
                self.json = json.loads(self.body)
                print(f"{self.form}")
        except Exception:
            self.error = "Body Parsing Error"
