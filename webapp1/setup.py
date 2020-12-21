import sys
sys.path.append("..")

import protocol.reference as sec

name = input("Service Name: ")
URL = input("Service URL: ")

cert, privkey_sign, privkey_recv = sec.Certificate.newService(name, URL)

password = input("Service Password: ")

sec.storeCert(cert, privkey_sign, privkey_recv, to="storage/service_cert/service", passphrase=password)

f = open("storage/service_cert/passphrase", "w")
f.write(password)
f.close()