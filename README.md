# decrypt-winrm

(use python3)

modified/forked from this gist https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045/ by @jborean93

install requirements:
`pip3 install -r requirements.txt`

example usage:
`python3 winrm_decrypt.py -n 8bb1f8635e5708eb95aedf142054fc95 ./capture.pcap`

(you can find the working example pcap inside [examples](examples), capture.pcap from HTB Uni CTF Quals 2021

or, use the password
`python3 winrm_decrypt.py -p password123 ./capture.pcap`

