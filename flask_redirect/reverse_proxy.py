import socket
from threading import Thread

class Host:
    def __init__(self, host, port):
        self.host = host
        self.port = port

def handle_client(client_socket, backend):
    request_data = client_socket.recv(4096)

    # Forward the request to the backend server
    backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_socket.connect((backend.host, backend.port))
    backend_socket.sendall(request_data)

    # Receive the response from the backend server
    response_data = backend_socket.recv(4096)

    # Send the response back to the client
    client_socket.sendall(response_data)

    # Close the sockets
    backend_socket.close()
    client_socket.close()

def run_proxy(proxy, backend):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((proxy.host, proxy.port))
    proxy_socket.listen(10)

    print(f"Proxy server listening on {proxy.host}:{proxy.port}")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")

        # Start a new thread to handle the client
        client_thread = Thread(target=handle_client, args=(client_socket, backend))
        client_thread.start()

if __name__ == '__main__':
    #                                   default localhost
    #                                   vvvvvvvvvvvvvvvvv
    proxy_ip = '10.20.30.4'
    run_proxy(Host(proxy_ip, 80), Host('127.0.0.1', 8000))

def proxy_attack(attacker_ip):
    run_proxy(Host(attacker_ip, 80), Host('127.0.0.1', 8000))