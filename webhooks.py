#!/usr/bin/env python
import io
import os
import re
import sys
import hmac
import json
import subprocess

from hashlib import sha1
from flask import Flask, request, abort

# https://github.com/razius/github-webhook-handler
# https://github.com/oar-team/sphinx-webhook-builder

app = Flask(__name__)
app.debug = True
app.env = 'development'
app.testing = True


if os.environ.get('USE_PROXYFIX', None):
    from werkzeug.contrib.fixers import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app)


REPOSITORIES_JSON = os.path.join(os.getcwd(), 'repositories.json')


@app.route('/')
def hello():
    return "Hello World!"


@app.route('/webhooks', methods=['GET', 'POST'])
def webhooks():
    if request.method == 'GET':
        return 'Invalid hook payload.'
    elif request.method == 'POST':
        if request.headers.get('X-GitHub-Event') == "ping":
            return json.dumps({'msg': 'Hi!'})
        if request.headers.get('X-GitHub-Event') != "push":
            return json.dumps({'msg': "wrong event type"})

        repositories = json.loads(io.open(REPOSITORIES_JSON, 'r').read())

        payload = json.loads(request.data)
        repo_meta = {
            'name': payload.get('repository').get('name'),
            'owner': payload.get('repository').get('owner').get('name') if payload.get('repository').get('owner') else payload.get('project').get('namespace')
        }

        repo = None
        # Try to match on branch as configured in repos.json
        match = re.match(r"refs/heads/(?P<branch>.*)", payload.get('ref'))
        if match:
            repo_meta['branch'] = match.groupdict()['branch']
            repo = repositories.get('{owner}/{name}/branch:{branch}'.format(**repo_meta), None)
            # Fallback to plain owner/name lookup
            if not repo:
                repo = repositories.get('{owner}/{name}'.format(**repo_meta), None)

        if repo and repo.get('path', None):
            # Check if POST request signature is valid
            key = repo.get('key', None)
            if key:
                signature = request.headers.get('X-Hub-Signature').split('=')[1]
                if type(key) == unicode:
                    key = key.encode()
                mac = hmac.new(key, msg=request.data, digestmod=sha1)
                if not compare_digest(mac.hexdigest(), signature):
                    abort(403)

        if repo.get('action', None):
            for action in repo['action']:
                process = subprocess.Popen(action, cwd=repo.get('path', '.'))
                process.wait()

        return json.dumps({'msg': 'Done!'})


# Check if python version is less than 2.7.7
if sys.version_info < (2, 7, 7):
    # http://blog.turret.io/hmac-in-go-python-ruby-php-and-nodejs/
    def compare_digest(a, b):
        if len(a) != len(b):
            return False
        result = 0
        for ch_a, ch_b in zip(a, b):
            result |= ord(ch_a) ^ ord(ch_b)
        return result == 0
else:
    compare_digest = hmac.compare_digest


if __name__ == '__main__':
    try:
        port_number = int(sys.argv[1])
    except:
        port_number = 80
    if os.environ.get('USE_PROXYFIX', None) == 'true':
        app.wsgi_app = ProxyFix(app.wsgi_app)
    app.run(host='0.0.0.0', port=port_number)
