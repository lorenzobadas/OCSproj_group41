from flask import Flask, request, redirect

app = Flask(__name__)

@app.before_request
def before_request():
    if not request.is_secure and request.headers.get('X-Forwarded-Proto', '') != 'https':
        # Redirect to HTTPS version of the same URL
        url = request.url.replace('http://', 'https://', 1)
        response = redirect(url, code=301)
        response.headers['pragma'] = 'no-cache'
        response.headers['cache-control'] = 'no-cache, no-store, must-revalidate'
        return response

@app.after_request
def after_request(response):
    if request.is_secure and request.headers.get('X-Forwarded-Proto', '') == 'https':
        # Redirect to HTTP version of the same URL
        url = request.url.replace('https://', 'http://', 1)
        response = redirect(url, code=301)
        response.headers['pragma'] = 'no-cache'
        response.headers['cache-control'] = 'no-cache, no-store, must-revalidate'
        return response
    return response

if __name__ == '__main__':
    app.run(port=8000)
