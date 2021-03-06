"""
    SEC v1.0
    ========
    Reference Implementation.
"""

import os

from datetime import datetime
from base64 import b64encode, b64decode
from more_itertools import sliced

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import PublicFormat, PrivateFormat
from cryptography.hazmat.primitives.serialization import Encoding, BestAvailableEncryption, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


class Certificate:

    def __init__(self, Type,
                 Name,
                 Handle,
                 PubkeySign,
                 PubkeyRecv,
                 Flags,
                 IssuedDate,
                 Authorize):
        """
            DO NOT EVER CALL Certificate.__init__!
            Use any of the other provided methods for Instantiation, namely:

             * Certificate.newService
             * Certificate.newUser
             * Certificate.new
             * CertFile.load

            DO NOT USE THIS METHOD. This method is for internal use only!
        """
        self.Type = Type
        self.Name = Name
        self.Handle = Handle
        self.PubkeySign = PubkeySign
        self.PubkeyRecv = PubkeyRecv
        self.Flags = Flags
        self.IssuedDate = IssuedDate
        self.Authorize = Authorize

    def build(self):
        """
            Certificate.build returns a copy of the certificate,
            in the scheme defined in the SECTP standard.
        """

        pubkey_sign = self.PubkeySign.public_numbers().n
        pubkey_recv = self.PubkeyRecv.public_numbers().n

        pubkey_sign = b64encode(
            str(pubkey_sign).encode("utf-8")).decode("utf-8")
        pubkey_recv = b64encode(
            str(pubkey_recv).encode("utf-8")).decode("utf-8")

        pubkey_sign = "\n".join(sliced(pubkey_sign, 42))
        pubkey_recv = "\n".join(sliced(pubkey_recv, 42))

        return \
            f"""
+++SECTP.1/Certfile+++
Type: {self.Type}
Name: {self.Name}
Handle: {self.Handle}
PubkeySign: |
{pubkey_sign}
PubkeyRecv: |
{pubkey_recv}
Flags: {", ".join(self.Flags) if len(self.Flags) > 0 else "-"}
IssuedDate: {self.IssuedDate.isoformat()}
Authorize: {"self" if self.Authorize is None else self.Authorize.Handle}
""".strip()

    def build_signed(self, privkey_sign):
        certificate = self.build()
        signature = privkey_sign.sign(
            certificate.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature = b64encode(signature).decode("utf-8")

        signature_line = "***signed: " + \
            signature + " at " + str(datetime.now())

        return certificate + "\n" + signature_line

    @classmethod
    def new(cls, Type, Name, Handle, Flags, Authorize):
        """
            Creates a new Certificate according to the SECTP Standard.
            Params:
                :Type: which can be either "Service" or "User"
                :Name: which is a string
                :Handle: which is for Services the URL, for Users the User Handle
                :Flags: which is a list of valid flags
                :Authorize: which is either None or the Certificate of the Service authorizing
            Returns:
                (new Certificate, privkey_sign, privkey_recv)

            PREFER USING Certificate.newService OR Certificate.newUser TO THIS METHOD!
        """

        if Type == "Service":
            key_sign = _generateKeys(4096)
            key_recv = _generateKeys(4096)
        else:
            key_sign = _generateKeys(2048)
            key_recv = _generateKeys(2048)

        pubkey_sign, privkey_sign = key_sign
        pubkey_recv, privkey_recv = key_recv

        return Certificate(Type, Name, Handle, pubkey_sign, pubkey_recv,
                           Flags, datetime.now(), Authorize), privkey_sign, privkey_recv

    @classmethod
    def newService(cls, Name, URL):
        """
            Creates a new Service Certificate according to the SECTP Standard.
            Params:
                :Name: which is a string
                :URL: which is the URL this Service is available under
            Returns:
                (new Certificate, privkey_sign, privkey_recv)
        """
        return cls.new("Service", Name, URL, [], None)

    @classmethod
    def newUser(cls, Name, Handle, Flags, Authorize):
        """
            Creates a new Certificate according to the SECTP Standard.
            Params:
                :Name: which is a string
                :Handle: which is the User Handle
                :Flags: which is a list of valid flags
                :Authorize: which is the Certificate of the Service authorizing
            Returns:
                (new Certificate, privkey_sign, privkey_recv)

        """
        return cls.new("User", Name, Handle, Flags, Authorize)


class CertFile:

    def __init__(self, certfile, cert, signature=None):
        self._cert = cert
        self._certfile = certfile
        self._signature = signature

    def cert(self, _authorize_cert=None, _no_verify=False):
        if _authorize_cert is not None:
            if _no_verify or self.verify(_authorize_cert):
                self._cert.Authorize = _authorize_cert
        else:
            self._cert.Authorize = None

        return self._cert

    def verify(self, _authorize_cert=None):
        self.cert(_authorize_cert, _no_verify=True)

        if _authorize_cert is None:
            _authorize_cert = self._cert.PubkeySign
        else:
            if _authorize_cert.Handle != self._cert.Authorize.Handle and _authorize_cert.Handle != self._cert.Handle:
                return False

            _authorize_cert = _authorize_cert.PubkeySign

        try:
            _authorize_cert.verify(
                b64decode(self._signature.encode("utf-8")),
                self._certfile.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except SyntaxError:  # InvalidSignature:
            return False
        else:
            return True

    @classmethod
    def load(cls, file_name):
        f = open(file_name, "r")
        contents = f.read()
        f.close()

        return cls.parse(contents)

    @classmethod
    def parse(self, certfile):
        certfile = certfile.split("\n")
        if certfile[0] != "+++SECTP.1/Certfile+++":
            raise ValueError("Invalid Certfile: missing header")
        if certfile[-1].startswith("***signed: "):
            signature_line = certfile[-1]
            orig_certfile = "\n".join(certfile[:-1])
            certfile = certfile[1:-1]
        else:
            signature_line = None
            orig_certfile = "\n".join(certfile[:])
            certfile = certfile[1:]

        signature = signature_line.split(" ")[1]

        certdata = _readFormat(certfile)

        pubkey_sign_nums = rsa.RSAPublicNumbers(65537, int(
            b64decode(certdata["PubkeySign"].encode("utf-8")).decode("utf-8")))
        pubkey_recv_nums = rsa.RSAPublicNumbers(65537, int(
            b64decode(certdata["PubkeyRecv"].encode("utf-8")).decode("utf-8")))

        cert = Certificate(Type=certdata["Type"],
                           Name=certdata["Name"],
                           Handle=certdata["Handle"],
                           PubkeySign=pubkey_sign_nums.public_key(
                               backend=default_backend()),
                           PubkeyRecv=pubkey_recv_nums.public_key(
                               backend=default_backend()),
                           Flags=certdata["Flags"].split(
                               ", ") if certdata["Flags"] != "-" else [],
                           IssuedDate=datetime.fromisoformat(
                               certdata["IssuedDate"]),
                           Authorize=certdata["Authorize"]
                           )

        return CertFile(orig_certfile, cert, signature)


class Message:

    def __init__(self, Subject,
                 DataType,
                 Body,
                 Author,
                 Recipient,
                 MessageDate):
        """

        """
        self.Subject = Subject
        self.DataType = DataType
        self.Body = Body
        self.Author = Author
        self.Recipient = Recipient
        self.MessageDate = MessageDate

    def encrypt(self, recipient_cert):
        """
            Message.encrypt encrypts the message as specified in the
            SECTP standard and returns a :_MessageWrapper: object.
        """

        body = b64encode(self.Body).decode("utf-8")
        body = "\n".join(sliced(body, 42))

        inner_template = \
            f"""
Subject: {self.Subject}
DataType: {self.DataType}
Body: |
{body}
""".strip()

        key = Fernet.generate_key()
        f = Fernet(key)
        ct = f.encrypt(inner_template.encode("utf-8"))

        return _MessageWrapper(ct, key, self, recipient_cert)


class _MessageWrapper:

    def __init__(self, cryptotext, full_key, message, recipient_cert):
        self.cryptotext = cryptotext
        self.full_key = full_key
        self.message = message
        self.recipient_cert = recipient_cert

    def build(self):
        private_key = self.recipient_cert.PubkeyRecv.encrypt(
            self.full_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        key = b64encode(private_key).decode("utf-8")

        message = b64encode(self.cryptotext).decode("utf-8")
        message = "\n".join(sliced(message, 42))

        return \
            f"""
+++SECTP.1/Message+++
Author: {self.message.Author.Handle}
Key: {key}
Message: |
{message}
MessageDate: {self.message.MessageDate.isoformat()}
""".strip()

    def build_signed(self, privkey_sign):
        message = self.build()
        signature = privkey_sign.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature = b64encode(signature).decode("utf-8")

        signature_line = "***signed: " + \
            signature + " at " + str(datetime.now())

        return message + "\n" + signature_line


class MessageLoader:

    def __init__(self, orig_message, msgdata, signature):
        self._orig_message = orig_message
        self._msgdata = msgdata
        self._signature = signature

    def author_untrusted(self):
        return self._msgdata["Author"]

    def get_origin_untrusted(self):
        return self.author_untrusted().split("@")[::-1]

    def date_untrusted(self):
        return self._msgdata['MessageDate']

    def verify(self, cert):
        if self.author_untrusted() != cert.Handle:
            return False
        try:
            cert.PubkeySign.verify(
                b64decode(self._signature.encode("utf-8")),
                self._orig_message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        else:
            return True

    def decrypt(self, key):
        session_key = b64decode(self._msgdata["Key"].encode("utf-8"))
        session_key = key.decrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        f = Fernet(session_key)
        inner_message = f.decrypt(
            b64decode(self._msgdata["Message"].encode("utf-8")))
        inner_message = inner_message.decode("utf-8").split("\n")
        msgdata = self._msgdata
        msgdata.update(_readFormat(inner_message))
        del msgdata["Message"], msgdata["Key"]
        msgdata["Body"] = b64decode(msgdata["Body"].encode("utf-8"))

        return Message(
            msgdata["Subject"],
            msgdata["DataType"],
            msgdata["Body"],
            msgdata["Author"],
            None,
            datetime.fromisoformat(
                msgdata["MessageDate"]))

    @classmethod
    def load(cls, file_name):
        f = open(file_name, "r")
        contents = f.read()
        f.close()

        return cls.parse(contents)

    @classmethod
    def parse(self, message):
        message = message.split("\n")
        if message[0] != "+++SECTP.1/Message+++":
            raise ValueError("Invalid message: missing header")
        if message[-1].startswith("***signed: "):
            signature_line = message[-1]
            orig_message = "\n".join(message[:-1])
            message = message[1:-1]
        else:
            signature_line = None
            orig_message = "\n".join(message[:])
            message = message[1:]

        signature = signature_line.split(" ")[1]

        msgdata = _readFormat(message)

        return MessageLoader(orig_message, msgdata, signature)


def _generateKeys(length):
    privkey = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=length)
    pubkey = privkey.public_key()
    return pubkey, privkey


def storeCert(cert, privkey_sign, privkey_recv, to, sign=None, passphrase="-"):
    if sign is None:
        sign = privkey_sign

    passphrase = passphrase.encode("utf-8")

    f = open(to + ".certfile", "w")
    f.write(cert.build_signed(sign))
    f.close()

    f = open(to + ".sign.privkey", "wb")
    pem = privkey_sign.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase)
    )
    f.write(pem)
    f.close()

    f = open(to + ".recv.privkey", "wb")
    pem = privkey_recv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase)
    )
    f.write(pem)
    f.close()


def outputPrivateKey(key, passphrase="-"):
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(
            passphrase.encode("utf-8"))
    )
    return pem.decode("utf-8")


def loadPrivateKey(to, type, passphrase="-"):
    passphrase = passphrase.encode("utf-8")

    f = open(to + "." + type + ".privkey", "rb")
    pem = f.read()
    f.close()

    return load_pem_private_key(
        pem, password=passphrase, backend=default_backend())


def inputPrivateKey(pem, passphrase="-"):
    passphrase = passphrase.encode("utf-8")
    return load_pem_private_key(
        pem, password=passphrase, backend=default_backend())


def _readFormat(format):
    data = {}
    i = 0
    while i < len(format):
        line = format[i]
        key, value = line.split(": ", 1)
        if value == "|":
            value = ""
            i += 1
            while i < len(format) and ": " not in format[i]:
                value += format[i]
                i += 1
            # Decrement once more at last. So that the end line is counted
            # normally too
            i -= 1

        data[key.strip()] = value.strip()
        i += 1

    return data
