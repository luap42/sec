"""
    SEC v1.0
    ========
    Reference Implementation.
"""

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
            DO NOT CALL Certificate.__init__!
            Use any of the other provided methods for Instantiation, namely:

             * Certificate.new
             * Certificate.loadFromFile

            DO NOT USE THIS METHOD. This method is for internal use only!
        """
        self.Type           = Type
        self.Name           = Name
        self.Handle         = Handle
        self.PubkeySign     = PubkeySign
        self.PubkeyRecv     = PubkeyRecv
        self.Flags          = Flags
        self.IssuedDate     = IssuedDate
        self.Authorize      = Authorize

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
        pass

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


class Message:
    pass

