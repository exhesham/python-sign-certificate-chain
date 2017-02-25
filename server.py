from certificateAPI import sign_cert
from flask import Flask, jsonify, request
from flask import render_template
from OpenSSL import SSL

app = Flask(__name__)

context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('server_key.key')
context.use_certificate_file('server_cert.crt')



@app.route('/<name>')
@app.route('/')
def main_template(name=None):
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
                    }), 200


if __name__ == '__main__':
    app.run(debug=True, port=8081)
