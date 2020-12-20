from protocol.reference import *

def task1():
    cert, privkey_sign, privkey_recv = Certificate.newService("Omega", "omega.localhost:5000")

    storeCert(cert, privkey_sign, privkey_recv, "data/omega")

    ucert, uprivkey_sign, uprivkey_recv = Certificate.newUser("Paul Strobach", "luap42@omega.localhost:5000", ["verified"], cert)

    storeCert(ucert, uprivkey_sign, uprivkey_recv, "data/luap42", sign=privkey_sign)

def task2():
    certfile  = CertFile.load("data/omega.certfile")
    ucertfile = CertFile.load("data/luap42.certfile")
    print(certfile.verify())
    
    cert = certfile.cert()

    print(not ucertfile.verify())
    print(ucertfile.verify(cert))

def task3():
    certfile  = CertFile.load("data/omega.certfile")
    print(certfile.verify())
    privkey_sign = loadPrivateKey("data/omega", "sign")

    ucert, uprivkey_sign, uprivkey_recv = Certificate.newUser("The Codidact Foundation", "codidact@omega.localhost:5000", [], certfile.cert())
    storeCert(ucert, uprivkey_sign, uprivkey_recv, "data/codidact", sign=privkey_sign)

def task4():
    ucf = CertFile.load("data/codidact.certfile")
    cf = CertFile.load("data/omega.certfile")
    print(cf.verify())
    cert = cf.cert()
    print(cf.verify(cert))
    
    print(ucf.verify(cert))

print("\n\nTask 1:\n---")
task1()
print("\n\nTask 2:\n---")
task2()
print("\n\nTask 3:\n---")
task3()
print("\n\nTask 4:\n---")
task4()