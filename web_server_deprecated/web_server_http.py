import http.server

# Set up server address and port
server_address = ('', 8000)  # Listen on port 8000

# Create a simple HTTP request handler
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Extract username and password from the request
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        username = None
        password = None
        for item in post_data.split('&'):
            if item.startswith('username='):
                username = item[len('username='):]
                print(username)
            elif item.startswith('password='):
                password = item[len('password='):]
                print(password)

        # Check if username and password are valid (dummy check)
        if username and password:
            # Redirect to the landing page
            self.send_response(302)  # Redirect status code
            self.send_header('Location', '/welcome.html')  # URL of the landing page
            self.end_headers()
        else:
            # Invalid credentials, show login page again
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./pages/login.html', 'rb') as file:
                self.wfile.write(file.read())

    def do_GET(self):
        if self.path == '/login.html':
            # Serve the login page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./pages/login.html', 'rb') as file:
                self.wfile.write(file.read())
        elif self.path == '/welcome.html':
            # Serve the landing page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./pages/welcome.html', 'rb') as file:
                self.wfile.write(file.read())
        else:
            # Serve a 404 page for any other requests
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 Page Not Found')

# Create an HTTP server
http_server = http.server.HTTPServer(server_address, Handler)

# Start the server
http_server.serve_forever()
