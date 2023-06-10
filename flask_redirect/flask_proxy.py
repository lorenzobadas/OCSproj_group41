from flask import Flask, request, Response
import requests
import threading

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_request(path):
    # Get the intended URL from the request
    url = 'https://' + request.host + '/' + path

    # Forward the request to the intended URL
    response = requests.request(
        method=request.method,
        url=url,
        headers=request.headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,  # Disable automatic redirects
        verify=False  # Ignore SSL certificate verification
    )

    # Create a Flask response using the received response
    flask_response = Response(response.content, response.status_code, headers=dict(response.headers))

    return flask_response

if __name__ == '__main__':
    app.run(port=8000)

def flask_proxy(port):
    app.run(port=port)

def flask_proxy_thread():
    thread = threading.Thread(target=flask_proxy, args=(8000,))
    thread.start()