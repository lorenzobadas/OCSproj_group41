from flask import Flask, redirect, request

app = Flask(__name__)

@app.before_request
def before_request():
    print('Before')
    # Check if the request is secure (HTTPS)
    if not request.is_secure and request.headers.get('X-Forwarded-Proto', '') != 'https':
        # Redirect to HTTPS version of the same URL
        url = request.url.replace('http://', 'https://', 1)
        print(url)
        return redirect(url, code=301)

@app.after_request
def after_request(response):
    print('After')
    print(response)
    # Check if the response is secure (HTTPS)
    if not request.is_secure and request.host != 'localhost:8000':
        # Redirect to HTTP version of the same URL
        url = request.url.replace('https://', 'http://', 1)
        print(url)
        return redirect(url, code=301)
    print("Jump")
    return response

if __name__ == '__main__':
    app.run(port=8000)