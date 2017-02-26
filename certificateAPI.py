from OpenSSL.crypto import X509
import os, time, base64, sys
from M2Crypto import X509, EVP, RSA, ASN1, m2

root_issuer_c = "IL"
root_issuer_cn = "Hisham Authoritah"
intermediate_issuer_c = "IL"
intermediate_issuer_cn = "Hisham Intermediate Authoritah"


def callback(*args):
    pass


def mkreq(bits, ca=0, cn="exhesham ca group", c="IL"):
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
    cert.save("root.crt")
    pk.save_key("root.key", cipher=None)
    return cert, pk, pkey


def create_intermediate_cert(root_pkey=None):
    if not os.path.exists("root.key"):
        return 1, 'create root certificate'
    if not root_pkey:
        root_pkey = EVP.load_key("root.key")
    req, pk = mkreq(2048, ca=1, cn=intermediate_issuer_cn, c=intermediate_issuer_c)
    cert, pk, pkey = generate_and_sign_cert(req, pk, sign_key=root_pkey, issuer_cn=root_issuer_cn,
                                            issuer_c=root_issuer_c)
    pk.save_key("inter.key", cipher=None)
    cert.save("inter.crt")
    return cert, pk, pkey





def create_chain():
    '''Create certificate CA chain made of root and intermediate chain'''
    if os.path.exists('root.crt'):
        os.remove('root.crt')
    if os.path.exists('root.key'):
        os.remove('root.key')
    if os.path.exists('inter.crt'):
        os.remove('inter.crt')
    if os.path.exists('inter.key'):
        os.remove('inter.key')
    create_root_cert()
    create_intermediate_cert()


def sign_cert(cn, c):
    if not os.path.exists("root.crt") \
            or not os.path.exists("root.key") \
            or not os.path.exists("inter.crt") \
            or not os.path.exists("inter.key"):
        create_chain()
    inter_pkey = EVP.load_key("inter.key")
    req, pk = mkreq(2048, ca=1, cn=cn, c=c)
    cert, pk, pkey = generate_and_sign_cert(req, pk, sign_key=inter_pkey, issuer_cn=intermediate_issuer_cn,
                                            issuer_c=intermediate_issuer_c)
    return cert, pk, pkey
