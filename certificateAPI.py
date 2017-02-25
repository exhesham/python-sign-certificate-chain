import OpenSSL
from OpenSSL._util import lib as _lib, ffi as _ffi
from OpenSSL.crypto import _new_mem_buf, _bio_to_string, X509
import os, time, base64, sys
from M2Crypto import X509, EVP, RSA, Rand, ASN1, m2, util, BIO
import M2Crypto
##pip install --egg M2CryptoWin32
##pip install pyOpenSSL


root_issuer_c = "IL"
root_issuer_cn = "Hesham Authorita"
intermediate_issuer_c = "IL"
intermediate_issuer_cn = "Hisham Intermediate Authorita"


def aux_create_key():
    bio_priv = _new_mem_buf()
    res = None
    helper = OpenSSL.crypto._PassphraseHelper(OpenSSL.crypto.FILETYPE_PEM, None)

    pk = OpenSSL.crypto.PKey()
    pk.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

    # Convert from EVP_PKEY type to RSA type
    rsa_pkey = _lib.EVP_PKEY_get1_RSA(pk._pkey)
    try:
        result_code = _lib.PEM_write_bio_RSAPrivateKey(bio_priv, rsa_pkey, _ffi.NULL, _ffi.NULL, 0,
                                                       helper.callback, helper.callback_args)
        res = _bio_to_string(bio_priv)
    except TypeError:
        print "TypeError happened while generating.."
        return None
    return res


def callback(*args):
    pass


def mkreq(bits, ca=0, cn="OpenSSL Group", c="UK"):
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537, callback)
    pk.assign_rsa(rsa)
    rsa = None  # should not be freed here
    x.set_pubkey(pk)

    name = x.get_subject()
    name.C = c
    name.CN = cn
    if not ca:
        # ext1 = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
        ext1 = X509.new_extension('subjectAltName', 'DNS:' + cn)
        ext2 = X509.new_extension('nsComment', 'Hello there')
        extstack = X509.X509_Extension_Stack()
        extstack.push(ext1)
        extstack.push(ext2)
        x.add_extensions(extstack)
    # self.assertRaises(ValueError, x.sign, pk, 'sha513')
    x.sign(pk, 'sha1')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return x, pk


def create_root_cert():
    req, pk = mkreq(4096, ca=1, cn=root_issuer_cn, c=root_issuer_c)
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
    issuer.C = root_issuer_c
    issuer.CN = root_issuer_cn
    cert.set_issuer(issuer)
    cert.set_pubkey(pkey)
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)
    cert.sign(pk, 'sha1')

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
    pk.save_key("root.key",cipher=None)
    return cert, pk, pkey


def test_mkcacert():
    cacert, pk, pkey = create_root_cert()
    assert cacert.verify(pkey)


def create_intermediate_cert(root_pkey=None):
    if not os.path.exists("root.key"):
        return 1, 'create root certificate'
    #root_pkey = X509.load_cert("root.key", format=X509.FORMAT_PEM)
    if not root_pkey:
        root_pkey = EVP.load_key("root.key")
    req, pk = mkreq(2048, ca=1, cn=intermediate_issuer_cn, c=intermediate_issuer_c)
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
    issuer.C = root_issuer_c
    issuer.CN = root_issuer_cn
    cert.set_issuer(issuer)
    cert.set_pubkey(pkey)
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)
    cert.sign(root_pkey, 'sha1')
    pk.save_key("inter.key", cipher=None)
    cert.save("inter.crt")
    return cert, pk, pkey


def create_chain():
    if os.path.exists('root.crt'):
        os.remove('root.crt')
    if os.path.exists('root.key'):
        os.remove('root.key')
    if os.path.exists('inter.crt'):
        os.remove('inter.crt')
    if os.path.exists('inter.key'):
        os.remove('inter.key')
    cert, pk, pkey = create_root_cert()
    create_intermediate_cert()


def sign_cert(cn, c, sever_cert=True):
    if not os.path.exists("root.crt") \
            or not os.path.exists("root.key") \
            or not os.path.exists("inter.crt") \
            or not os.path.exists("inter.key"):
        create_chain()
    inter_pkey = EVP.load_key("inter.key")
    req, pk = mkreq(2048, ca=1, cn=cn, c=c)
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
    issuer.C = intermediate_issuer_c
    issuer.CN = intermediate_issuer_cn
    cert.set_issuer(issuer)
    cert.set_pubkey(pkey)
    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)
    cert.sign(inter_pkey, 'sha1')
    return cert, pk, pkey

#create_chain()
#create_root_cert()
# cert.save("root.crt")
# cert, pk, pkey  = create_intermediate_cert(pk)
# cert.save("inter.crt")
# cert, pk, pkey  = sign_cert(pk)
# cert.save("cert.crt")
