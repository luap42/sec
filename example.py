from protocol.reference import *

def task1():
    cert, privkey_sign, privkey_recv = Certificate.newService("Omega", "omega.localhost:5000")

    f = open("data/omega.certfile", "w")
    f.write(cert.build_signed(privkey_sign))
    f.close()

    ucert, uprivkey_sign, uprivkey_recv = Certificate.newUser("Paul Strobach", "luap42@omega.localhost:5000", ["verified"], cert)

    f = open("data/luap42.certfile", "w")
    f.write(ucert.build_signed(privkey_sign))
    f.close()

def task2():
    certfile  = CertFile.load("data/omega.certfile")
    ucertfile = CertFile.load("data/luap42.certfile")
    print(certfile.verify())
    
    cert = certfile.cert()

    print(ucertfile.verify())
    print(ucertfile.verify(cert))

task2()