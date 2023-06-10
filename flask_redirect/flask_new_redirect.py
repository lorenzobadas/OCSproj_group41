from flask import Flask, request, redirect

app = Flask(__name__)

@app.before_request
def before_request():
    if request.headers.get('X-Forwarded-Proto', '') != 'https' and request.host != 'localhost:8000':
        # Redirect to HTTPS version of the same URL
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.after_request
def after_request(response):
    if not request.is_secure and request.host != 'localhost:8000' and request.headers.get('X-Forwarded-Proto', '') == 'https':
        # Redirect to HTTP version of the same URL
        url = request.url.replace('https://', 'http://', 1)
        return redirect(url, code=301)
    return response

if __name__ == '__main__':
    app.run(port=8000)