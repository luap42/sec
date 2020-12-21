from protocol.reference import *
from datetime import datetime

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

def task5():
    cf = CertFile.load("data/luap42.certfile")
    rcf = CertFile.load("data/codidact.certfile")
    privkey_sign = loadPrivateKey("data/luap42", "sign")

    cf, rcf = cf.cert(), rcf.cert()

    m = Message("Hello World!", "text/raw", b"Hello World! This is a message", cf, rcf, datetime.now())
    mw = m.encrypt(rcf)
    
    f = open("data/message.msg.crypted", "w")
    f.write(mw.build_signed(privkey_sign))
    f.close()

def task6():
    cf = CertFile.load("data/luap42.certfile")
    privkey_recv = loadPrivateKey("data/codidact", "recv")

    cf = cf.cert()

    m = MessageLoader.load("data/message.msg.crypted")
    print(m.verify(cf))
    m = m.decrypt(privkey_recv)

    print(m.Subject)
    print(m.Body)
    

if False:
    pass
    print("\n\nTask 1:\n---")
    task1()
    print("\n\nTask 2:\n---")
    task2()
    print("\n\nTask 3:\n---")
    task3()
    print("\n\nTask 4:\n---")
    task4()
    print("\n\nTask 5:\n---")
    task5()
print("\n\nTask 6:\n---")
task6()