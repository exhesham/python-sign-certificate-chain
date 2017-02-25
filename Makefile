sudo -i
apt-get purge -y python-pip
wget https://bootstrap.pypa.io/get-pip.py
python ./get-pip.py
apt-get install python-pip
apt-get install python-dev

pip install pyopenssl
pip install --egg M2Crypto
pip install Flask