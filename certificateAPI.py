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

from OpenSSL.crypto import X509
import os, time, base64, sys
from M2Crypto import X509, EVP, RSA, ASN1, m2
import argparse

# Initialize command line
parser = argparse.ArgumentParser(description='my flags')
parser.add_argument('--root-c',action='store',dest='root_issuer_c', help='The root issuer country',default=['IL'], nargs=1, required=False)
parser.add_argument('--root-cn',action='store',dest='root_issuer_cn', help='The root issuer common name',default=['Hesham Authoritah'], nargs=1, required=False)
parser.add_argument('--inter-c',action='store',dest='intermediate_issuer_c', help='The intermediate country name',default=['IL'], nargs=1, required=False)
parser.add_argument('--inter-cn',action='store',dest='intermediate_issuer_cn', help='The intermediate issuer common name',default=['Hisham Intermediate Authoritah'], nargs=1, required=False)
parser.add_argument('--cn',action='store',dest='cert_cn', help='Common name of the certificate',default=['localhost'], nargs=1, required=False)
parser.add_argument('--c',action='store',dest='cert_c', help='Country of the certificate',default=['IL'], nargs=1, required=False)
parser.add_argument('--root-key-file',action='store',dest='root_key_file', help='The output root certificate file. if file exists, it will be overwritten',default=['root.key'], nargs=1, required=False)
parser.add_argument('--root-crt-file',action='store',dest='root_crt_file', help='The output root key certificate file. if file exists, it will be overwritten',default=['root.crt'], nargs=1, required=False)
parser.add_argument('--inter-key-file',action='store',dest='intermediate_key_file', help='The output intermediate certificate file. if file exists, it will be overwritten',default=['inter.key'], nargs=1, required=False)
parser.add_argument('--inter-crt-file',action='store',dest='intermediate_crt_file', help='The output intermediate key certificate file. if file exists, it will be overwritten',default=['inter.crt'], nargs=1, required=False)
parser.add_argument('--key-file',action='store',dest='key_file', help='The output certificate file. if file exists, it will be overwritten',default=['cert.key'], nargs=1, required=False)
parser.add_argument('--crt-file',action='store',dest='crt_file', help='The output key certificate file. if file exists, it will be overwritten',default=['cert.crt'], nargs=1, required=False)
parser.add_argument('--version', action='version', version=' 1.0')
parser.add_argument('--clean',dest='clean', help='Clean output files', required=False, action="store_true")
parser.add_argument('--cert',dest='create_cert', help='Create certificate', required=False, action="store_true")
parser.add_argument('--ca', dest='create_root', help='Create root certificate - if intermediate is not available, it will be created', required=False, action="store_true")

args = parser.parse_args()

# Global params
root_issuer_c = args.root_issuer_c[0]
root_issuer_cn = args.root_issuer_cn[0]
intermediate_issuer_c = args.intermediate_issuer_c[0]
intermediate_issuer_cn = args.intermediate_issuer_cn[0]
cert_cn = args.cert_cn[0]
cert_c = args.cert_c[0]
cert_key_file = args.key_file[0]
cert_file = args.crt_file[0]
root_key_file = args.root_key_file [0]
root_crt_file = args.root_crt_file[0]
intermediate_key_file = args.intermediate_key_file[0]
intermediate_crt_file = args.intermediate_crt_file[0]


def callback(*args):
    pass


def mkreq(bits, ca=0, cn=cert_cn, c=cert_c):
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537, callback)
    pk.assign_rsa(rsa)
    x.set_pubkey(pk)
    name = x.get_subject()
    name.C = c
    name.CN = cn
    if not ca:
        ext1 = X509.new_extension('subjectAltName', 'DNS:' + cn)
        ext2 = X509.new_extension('nsComment', 'Hello there')
        extstack = X509.X509_Extension_Stack()
        extstack.push(ext1)
        extstack.push(ext2)
        x.add_extensions(extstack)
    x.sign(pk, 'sha256')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return x, pk


def generate_and_sign_cert(req, pk, sign_key, issuer_cn, issuer_c):
    pkey = req.get_pubkey()
    sub = req.get_subject()
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    cert.set_subject(sub)
    t = long(time.time()) + time.timezone
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    nowPlusYear = ASN1.ASN1_UTCTIME()
    nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
    cert.set_not_before(now)
    cert.set_not_after(nowPlusYear)
    issuer = X509.X509_Name()
    issuer.C = issuer_c
    issuer.CN = issuer_cn
    cert.set_issuer(issuer)
    cert.set_pubkey(pkey)
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)
    cert.sign(sign_key, 'sha256')
    return cert, pk, pkey


def create_root_cert():
    if os.path.exists(root_crt_file):
        os.remove(root_crt_file)
    if os.path.exists(root_key_file):
        os.remove(root_key_file)

    req, pk = mkreq(4096, ca=1, cn=root_issuer_cn, c=root_issuer_c)
    cert, pk, pkey = generate_and_sign_cert(req, pk, sign_key=pk, issuer_cn=root_issuer_cn, issuer_c=root_issuer_c)
    if m2.OPENSSL_VERSION_NUMBER >= 0x0090800fL:
        assert cert.check_ca()
        assert cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 1)
        assert cert.check_purpose(m2.X509_PURPOSE_NS_SSL_SERVER, 1)
        assert cert.check_purpose(m2.X509_PURPOSE_ANY, 1)
        assert cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 0)
        assert cert.check_purpose(m2.X509_PURPOSE_NS_SSL_SERVER, 0)
        assert cert.check_purpose(m2.X509_PURPOSE_ANY, 0)
    else:
        return None, None, None
        # TODO:self.assertRaises(AttributeError, cert.check_ca)
    cert.save(root_crt_file)
    pk.save_key(root_key_file, cipher=None)
    return cert, pk, pkey


def create_intermediate_cert(root_pkey=None):

    if not os.path.exists(root_key_file):
        return 1, 'create root certificate'

    if not root_pkey:
        root_pkey = EVP.load_key(root_key_file)
    # Clean intermediate cert
    if os.path.exists(intermediate_crt_file):
        os.remove(intermediate_crt_file)
    if os.path.exists(intermediate_key_file):
        os.remove(intermediate_key_file)

    req, pk = mkreq(2048, ca=1, cn=intermediate_issuer_cn, c=intermediate_issuer_c)
    cert, pk, pkey = generate_and_sign_cert(req, pk, sign_key=root_pkey, issuer_cn=root_issuer_cn,
                                            issuer_c=root_issuer_c)
    pk.save_key(intermediate_key_file, cipher=None)
    cert.save(intermediate_crt_file)
    return cert, pk, pkey

def create_chain():
    '''Create certificate CA chain made of root and intermediate chain'''
    create_root_cert()
    create_intermediate_cert()

def clean_files():
    remove_file(root_crt_file)
    remove_file(root_key_file)
    remove_file(intermediate_crt_file)
    remove_file(intermediate_key_file)
    remove_file(cert_file)
    remove_file(cert_key_file)

def sign_cert(cn = cert_cn, c = cert_c):
    if not os.path.exists(root_crt_file) \
            or not os.path.exists(root_key_file) \
            or not os.path.exists(intermediate_crt_file) \
            or not os.path.exists(intermediate_key_file):
        create_chain()
    inter_pkey = EVP.load_key(intermediate_key_file)
    req, pk = mkreq(2048, ca=1, cn=cn, c=c)
    cert, pk, pkey = generate_and_sign_cert(req, pk, sign_key=inter_pkey, issuer_cn=intermediate_issuer_cn,
                                            issuer_c=intermediate_issuer_c)
    return cert, pk, pkey

def save_to_text_file(text, filename):
    remove_file(filename)
    with open(filename, "w") as text_file:
        text_file.write(text)

def remove_file(filename):
    if os.path.exists(filename):
        os.remove(filename)

def create_ca_signed_certificiate():
    signed_cert, key, pkey = sign_cert()
    save_to_text_file(signed_cert.as_pem(), cert_file)
    save_to_text_file(str(key.as_pem(cipher=None)), cert_key_file)

if __name__ == '__main__':
    if args.clean:
        print "Will clean files"
        clean_files()
    if args.create_root:
        print "Will create root certificate"
        create_root_cert()
    if args.create_cert:
        print "Will create a certificate"
        create_ca_signed_certificiate()


