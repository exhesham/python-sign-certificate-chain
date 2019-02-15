# Goal
The goal of this project is to sign a certificate Chain.
For testing purposes, working with self-signed results to be tricky as moving to CA Signed may result in inexpected behaviour.
this can be noticed mainly with `nodejs`.

# Environment
You can use the API manually or with command line as depicted below.
![create cert](./createcert.gif "Create Cert")

## Run Web Server API
This project will run a web server. With a WebUI Client you can create and download your certificates.
The backend will use the local root.crt and intermediate.crt to sign the requested certificate submitted by the client.

## Run  Manually
The script certificateAPI.py can be run manually in order to create the certificate

## Scenarios
* If the root and the intermediate certificates are not available, they will be generated automatically.
* If the parent chain certificates are available, then the server will use them to sign your certificates.

## Dependencies

### install pip:
`curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py`
`python get-pip.py`

Go to Environment variables and add the path `C:\Python27\Scripts` to the `PATH` variable

### install ssl packages
to be able to install the M2Crypto, you need to first install the c++ compiler for python2.7 package: http://aka.ms/vcpython27
```
apt-get install python-dev
pip install pyopenssl
# Install M2Crypto
pip install https://ci.appveyor.com/api/buildjobs/y7yri08k45mn5nlj/artifacts/dist/M2Crypto-0.30.1-cp27-cp27m-win_amd64.whl

```

If you would run the UI, then install flask:

```
pip install Flask
```

# WebUI
You need to install the libraries as mentioned in the makefile.
Afterward, You should run the server `server.py`
```
python server.py
```

Login to the website https://localhost:8081

There you should fill your certificate details

# CommandLine

```
python certificateAPI.py --clean  --ca --cert --cn localhost
```

The possible flags are:

```
python certificateAPI.py --help
usage: certificateAPI.py [-h] [--root-c ROOT_ISSUER_C]
                         [--root-cn ROOT_ISSUER_CN]
                         [--inter-c INTERMEDIATE_ISSUER_C]
                         [--inter-cn INTERMEDIATE_ISSUER_CN] [--cn CERT_CN]
                         [--c CERT_C] [--root-key-file ROOT_KEY_FILE]
                         [--root-crt-file ROOT_CRT_FILE]
                         [--inter-key-file INTERMEDIATE_KEY_FILE]
                         [--inter-crt-file INTERMEDIATE_CRT_FILE]
                         [--key-file KEY_FILE] [--crt-file CRT_FILE]
                         [--version] [--clean] [--cert] [--ca]

my flags

optional arguments:
  -h, --help            show this help message and exit
  --root-c ROOT_ISSUER_C
                        The root issuer country
  --root-cn ROOT_ISSUER_CN
                        The root issuer common name
  --inter-c INTERMEDIATE_ISSUER_C
                        The intermediate country name
  --inter-cn INTERMEDIATE_ISSUER_CN
                        The intermediate issuer common name
  --cn CERT_CN          Common name of the certificate
  --c CERT_C            Country of the certificate
  --root-key-file ROOT_KEY_FILE
                        The output root certificate file. if file exists, it
                        will be overwritten
  --root-crt-file ROOT_CRT_FILE
                        The output root key certificate file. if file exists,
                        it will be overwritten
  --inter-key-file INTERMEDIATE_KEY_FILE
                        The output intermediate certificate file. if file
                        exists, it will be overwritten
  --inter-crt-file INTERMEDIATE_CRT_FILE
                        The output intermediate key certificate file. if file
                        exists, it will be overwritten
  --key-file KEY_FILE   The output certificate file. if file exists, it will
                        be overwritten
  --crt-file CRT_FILE   The output key certificate file. if file exists, it
                        will be overwritten
  --version             show program's version number and exit
  --clean               Clean output files
  --cert                Create certificate
  --ca                  Create root certificate - if intermediate is not
                        available, it will be created


```

# Example
You can use up and running example by going to https://thunderclouding.ddns.net.
