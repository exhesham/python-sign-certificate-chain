'''
The MIT License (MIT)

Copyright (c) 2017 Thunderclouding.com - exhesham

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''

from certificateAPI import sign_cert
from flask import Flask, jsonify, request, Response
from flask import render_template
import os

app = Flask(__name__)

# context = SSL.Context(SSL.SSLv23_METHOD)
# context.use_privatekey_file('server_key.pem')
# context.use_certificate_file('server_cert.crt')

from flask import send_from_directory
@app.route('/image/<name>')
def image_logo(name):
    print "log from ",app.root_path
    return send_from_directory(os.path.join(app.root_path, 'templates'),
                               name, mimetype='image/vnd.microsoft.icon')

@app.route('/favicon.ico')
def favicon():
    print "favicon from ",app.root_path
    return send_from_directory(os.path.join(app.root_path, 'templates'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/<name>')
@app.route('/')
def main_template(name=None):
    print name
    if not name:
        name = 'index.html'
    return render_template(name, name=name)


@app.route('/sign_ca/sign', methods=['POST', 'GET'])
def sign_ca():
    content =  request.json
    if not content:
        return jsonify({'status': 'fail', 'msg': 'No fields were received!'}), 400

    cn = content.get('cn', None)
    c = content.get('c', None)
    if not c or not cn:
        return jsonify({'status': 'fail', 'msg': 'Not all fields were received!'}), 400
    signed_cert, key, pkey = sign_cert(cn, c)
    return jsonify({'status': 'success',
                    'ca_root':open('root.crt').read(),
                    'ca_inter':open('inter.crt').read(),
                    'signed_cert': signed_cert.as_pem(),
                    'key': str(key.as_pem(cipher=None))
                    }), 200, {'Content-Type': 'application/json; charset=utf-8'}


if __name__ == '__main__':
    app.run(debug=True, port=8081,host="0.0.0.0", ssl_context=('server_cert.crt','server_key.pem'),  threaded=True)
