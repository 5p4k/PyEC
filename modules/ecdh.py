"""
ecdh module - Safe (encrypted) session setup using Diffie-Hellman with elliptic curves.

ecdh provides only one class, ECDHSession, that using only routines as sendMessage,
messageReceived sets up a shared key and encrypts/decrypts messages.
ECDHSession does not provide a transport layer.

ecdh requires the modules ec, bigrange, cryptohelp and salsa20.
Uses logging.log.
"""

from ec import *
from cryptohelp import *
import hashlib
from bigrange import bigrange
from support.salsa20 import Salsa20
import re
from logging import *

EC_SETUP_NEEDED=0
EC_SENT=1
EC_RECEIVED_REPLIED=2
EC_REPLY_RECEIVED_ACCEPTED=3
EC_READY=4
EC_ERROR=-1

class ECDHSession(object):
    """
    This class handles a key setup with elliptic curves and Diffie-Hellman protocol
    in a message-based way.
    Provides also a basic encrypt/decrypt functionality based on Salsa20.
    The class is intended to be plugged into MsgBasedTCPClient/Server.

    The key exchange mechanism is achieved in the following way:

    ---------------------------------------------------------------------------------

         [[[EC_SETUP_NEEDED]]]                               [[[EC_SETUP_NEEDED]]]

    gen. "big" prime p
    gen. ellipt. c. ec
    gen. of a private int a
    choice of a generator g of C_K
    comput. of a*g
    (ec, g, a*g) -------------------------------------> ec, g, a*g received
                                                        gen of a private int b
             [[[EC_SENT]]]                              comput. of b*g
                                        /--------------- (b*g)
    b*g received <---------------------/
    comput. of ab*g                                         [[[EC_RECEIVED_REPLIED]]]
    derive key from ab*g
    setup encryption (salsa20)
    comput. hash of repr(ec)
    encrypt hash -------------------------------------> hash received.
                                                        comput. of ab*g
    [[[EC_REPLY_RECEIVED_ACCEPTED]]]                    derive key from ab*g
                                                        decrypt hash
                                                        compute own hash of repr(ec)
                                                        check if they're =
                                                        
                                                                  [[[EC_READY]]]

                                                        comput. hash of repr(a*g, b*g)
    hash received, decrypted <------------------------- encrypt hash
    compute own hash of (a*g, b*g)
    check against received if =

            [[[EC_READY]]]

    ---------------------------------------------------------------------------------
    """

    def __init__(self, sendRoutine):
        """
        Initialized a new instance of ECDHSession with status EC_SETUP_NEEDED.

        Input:
            sendRoutine     A callable object with the signature sendRoutine(msg).
                            This will be invoked to send messages through network.
        """
        super(ECDHSession, self).__init__()
        self._sendRoutine=sendRoutine
        self._status=EC_SETUP_NEEDED
        self._ec=self._g=self._ag=self._bg=self._a=self._b=self._abg=self._key=None
        self._s20=None

    def status(self):
        """
            The current status of the encrypted session. Let's call "client" the instance
            of ECDHSession where initECDH(...) gets called, "server" the recipient instance
            which replits to the client. Then the two classes will pass through the following
            status codes:

                client: EC_SETUP_NEEDED                     server: EC_SETUP_NEEDED
                        EC_SENT                                     EC_RECEIVED_REPLIED
                        EC_REPLY_RECEIVED_ACCEPTED                  EC_READY
                        EC_READY

            In case an error occurs, the status will be EC_ERROR.

                * EC_SETUP_NEEDED: no data has been exchanged yet.

                * EC_SENT: client status, an elliptic curve rational points group has been
                    chosen, as well as a generator and a private integer, and sent to the server.

                * EC_RECEIVED_REPLIED: server status, the setup packet sent by the client has
                    been received, a private integer has been chosen and the reply with the
                    multiple of the generator has been sent back to the client. Key has not been
                    set up yet, although all the needed information is known.

                * EC_REPLY_RECEIVED_ACCEPTED: the reply from the server has been accepted and a
                    key has been derived from the shared secret. The client sends back, to test
                    the connection, an encrypted string (actually the md5 hash of the elliptic
                    curve's representation).

                * EC_READY: either
                    > the server has received the encrypted md5, derived its key, checked
                      with success the hash against its own elliptic curve, and it's ready to send
                      and receive. At this point the server sends back the md5 hash of the two
                      public multiples of the generator (actually of their representations).
                    > the client has received the encrypted md5 back from the server, checked
                      it against its own known values, successfully.
                    With EC_READY, the trasmission of user data can begin.
        """
        return self._status

    def initECDH(self):
        """
        Initiates key exchange mechanism. Read status() or the class documentation for the details.
        """
        if self._status!=EC_SETUP_NEEDED:
            return # wrong status

        # generate setup parameters
        self._ec, self._g, self._a, self._ag=ecdh_init(2)

        # prepare the message to be sent
        msg=str((self._ec._a, self._ec._b, self._ec._c, self._ec._p, self._g._x, self._g._y, self._ag._x, self._ag._y))
        # send it
        self._sendRoutine(msg)

        self._status=EC_SENT

    @staticmethod
    def _stringToListOfLongs(str):
        str="".join(str.split()) # strip all whitespace
        if not re.match("^\((\d+(L|),)*\d+(L|)\)$", str):
            return None
        pieces=str[1:len(str)-1].split(",")

        retval=[]
        for piece in pieces:
            retval.append(long(piece))

        return retval

    def sendEncryptedMessage(self, msg):
        """
        This method works only if the session in in status==EC_READY.
        Uses the shared key to encrypt with a stream cipher the message (Salsa20) and sends
        it to the recipient with calling the sendRoutine given in __init__.

        Input:
            msg         Plaintext message
        """
        if self._s20==None: return

        if len(msg)<20:
            log(LOG_INFO, "ecdh", "encrypting {}".format(repr(msg)))
        else:
            log(LOG_INFO, "ecdh", "encrypting {}...".format(repr(msg[0:20])))

        # set length, pad, send
        msg=str(len(msg))+"|"+msg
        if len(msg)%64!=0:
            msg+=" "*(64-(len(msg)%64))

        msg=self._s20.encrypt(msg)

        if len(msg)<20:
            log(LOG_INFO, "ecdh", "sending {}".format(repr(msg)))
        else:
            log(LOG_INFO, "ecdh", "sending {}...".format(repr(msg[0:20])))

        self._sendRoutine(msg)

    def decryptReceivedMessage(self, msg):
        """
        This method works only if the session in in status==EC_READY.
        Uses the shared key to decrypt msg and returns it as plaintext.

        Input:
            msg         Ciphertext

        Output:
            Plaintext string.
        """
        if self._s20==None: return

        if len(msg)<20:
            log(LOG_INFO, "ecdh", "decrypting {}".format(repr(msg)))
        else:
            log(LOG_INFO, "ecdh", "decrypting {}...".format(repr(msg[0:20])))

        # decrypt & extract
        msg=self._s20.decrypt(msg)
        pieces=msg.split("|",1)
        length=long(pieces[0])
        msg=pieces[1][0:length]
        
        return msg

    def messageReceived(self, msg):
        """
        The main method that handles the whole key-exchange mechanism. This should be called by
        the classes that handle the network layer when a message is received.

        Input:
            msg         Binary strings that represents the raw message.

        Output:
            Always True, except if an error occured.

        """
        if self._status==EC_SETUP_NEEDED:

            # we expect msg to be 8 integers
            params=ECDHSession._stringToListOfLongs(msg)
            if params==None or len(params)!=8:
                self._status=EC_ERROR
                log(LOG_ERROR, "ecdh", "invalid DH setup vector")
                return False

            # ok setup!
            self._a, self._b, self._c, self._p=params[0:4]
            self._ec=EC(self._a, self._b, self._c, self._p)

            self._g=ECPt(self._ec, params[4], params[5])
            self._ag=ECPt(self._ec, params[6], params[7])

            # compute a valid reply and send it
            self._b, self._bg, self._abg=ecdh_reply(self._p, self._g, self._ag)

            msg=str((self._bg._x, self._bg._y))
            self._sendRoutine(msg)

            self._status=EC_RECEIVED_REPLIED

            return True

        elif self._status==EC_SENT:

            # we expect msg to be 2 integers
            params=ECDHSession._stringToListOfLongs(msg)
            if params==None or len(params)!=2:
                self._status=EC_ERROR
                log(LOG_ERROR, "ecdh", "invalid DH reply vector")
                return False

            self._bg=ECPt(self._ec, params[0], params[1])

            # compute the shared secret now
            self._abg, self._key=ecdh_accept(self._a, self._bg)

            self._status=EC_REPLY_RECEIVED_ACCEPTED

            # print all the info
            log(LOG_INFO, "ecdh", "key exchange done. Parameters:")
            log(LOG_INFO, "          curve - "+str(self._ec))
            log(LOG_INFO, "    generator g - "+str(self._g))
            log(LOG_INFO, "       secret a - "+str(self._a))
            log(LOG_INFO, "            a*g - "+str(self._ag))
            log(LOG_INFO, "            b*g - "+str(self._bg))
            log(LOG_INFO, "    secret ab*g - "+str(self._abg))
            log(LOG_INFO, "            key - "+self._key[0:24].encode("hex"))
            log(LOG_INFO, "                  "+self._key[24:].encode("hex"))

            # setup the salsa encryptor... and send a previoulsy agreed message!
            self._s20=Salsa20(self._key[0:32], self._key[32:40], 20)

            log(LOG_INFO, "ecdh", "sending the hash of ec as reply")

            # that is, for example, the md5 of str(ec)
            msg=hashlib.md5(str(self._ec)).digest()

            # send it
            self.sendEncryptedMessage(msg)

            return True

        elif self._status==EC_RECEIVED_REPLIED:

            # we're expecting the md5 hash of self.ec! but first setup key
            self._key=ecdh_derivekey(self._abg)

            # print all the info
            log(LOG_INFO, "ecdh", "key exchange done. Parameters:")
            log(LOG_INFO, "          curve - "+str(self._ec))
            log(LOG_INFO, "    generator g - "+str(self._g))
            log(LOG_INFO, "       secret b - "+str(self._b))
            log(LOG_INFO, "            a*g - "+str(self._ag))
            log(LOG_INFO, "            b*g - "+str(self._bg))
            log(LOG_INFO, "    secret ab*g - "+str(self._abg))
            log(LOG_INFO, "            key - "+self._key[0:24].encode("hex"))
            log(LOG_INFO, "                  "+self._key[24:].encode("hex"))

            # setup salsa and decode message
            self._s20=Salsa20(self._key[0:32], self._key[32:40], 20)

            msg=self.decryptReceivedMessage(msg)
            hsh=hashlib.md5(str(self._ec)).digest()

            if msg!=hsh:
                # wrong message! failure
                log(LOG_ERROR, "ecdh", "wrong acknowledged message")
                log(LOG_ERROR, "      received - "+msg.encode("hex"))
                log(LOG_ERROR, "      expected - "+hsh.encode("hex"))
                self._status=EC_ERROR
                return False

            # it's ok! we're ready
            self._status=EC_READY

            log(LOG_INFO, "ecdh", "replying with the hash of a*g, b*g")

            # send back reply, that is, the hash of g^a and g^b
            msg=hashlib.md5(str(self._ag)+str(self._bg)).digest()

            self.sendEncryptedMessage(msg)

            log(LOG_IMPORTANTINFO, "ecdh", "encrypted session ready")

            return True

        elif self._status==EC_REPLY_RECEIVED_ACCEPTED:

            log(LOG_INFO, "ecdh", "checking message against a*g, b*g hash")

            # we expect msg to be the hash of str(ag)+str(bg)
            hsh=hashlib.md5(str(self._ag)+str(self._bg)).digest()
            msg=self.decryptReceivedMessage(msg)

            if hsh!=msg:
                # wrong message! failure
                log(LOG_ERROR, "ecdh", "wrong acknowledged reply message")
                self._status=EC_ERROR
                return False

            # we're ready!
            self._status=EC_READY

            log(LOG_IMPORTANTINFO, "ecdh", "encrypted session ready")

            return True

        elif self._status==EC_READY:

            # decrypt and print!
            log(LOG_INFO, "ecdh", "received encrypted message")
            msg=self.decryptReceivedMessage(msg)
            log(LOG_INCOMING, ""+msg)

            return True

        else:

            log(LOG_ERROR, "ecdh", "invalid status")

            return False

