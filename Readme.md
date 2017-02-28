# Goal
The goal of this project is to sign a certificate with a CA authority.
The best use-case for signing a certificate with a CA without paying any nickel or waiting for an authority to sign it
is for testing purpuses.

#Environment
This project will run a web server. With a WebUI Client you can create and download your certificates.
The backend will use the local root.crt and intermediate.crt to sign the requested certificate submitted by the client.

##Scenarios
If the root and the intermediate certificates are not available, they will be generated automatically.
IF the parent chain certificates are available, then the server will use them to sign your certificates.

##Dependencies
```
apt-get install python-dev
pip install pyopenssl
pip install --egg M2Crypto
pip install Flask
```

# Install
You need to install the libraries as mentioned in the makefile.
Afterward, You should run the server server.py

``
python server.py
``
Login to the website https://localhost:8081

There you should fill your certificate details

# Example
You can use up and running example by going to https://thunderclouding.ddns.net.