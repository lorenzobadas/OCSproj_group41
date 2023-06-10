import socket
from threading import Thread

# Define the backend server address (your Flask application)
backend_host = '127.0.0.1'
backend_port = 8000

# Define the proxy server address
proxy_host = '10.20.30.10'
proxy_port = 443

def handle_client(client_socket):
    request_data = client_socket.recv(4096)

    # Forward the request to the backend server
    backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_socket.connect((backend_host, backend_port))
    backend_socket.sendall(request_data)

    # Receive the response from the backend server
    response_data = backend_socket.recv(4096)

    # Send the response back to the client
    client_socket.sendall(response_data)

    # Close the sockets
    backend_socket.close()
    client_socket.close()

def run_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((proxy_host, proxy_port))
    proxy_socket.listen(10)

    print(f"Proxy server listening on {proxy_host}:{proxy_port}")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")

        # Start a new thread to handle the client
        client_thread = Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == '__main__':
    run_proxy()