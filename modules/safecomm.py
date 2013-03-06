"""
safecomm.py - ECDH protected message-based communications

safecomm subclasses netcomm's classes and hijacks the control of the messages flow
to an ECDHSession object.
Requires of course netcomm and ecdh.
Uses logging.log.
"""
from netcomm import *
from ecdh import ECDHSession
from logging import *

class ECDHClient(MsgBasedTCPClient):
    """
    Subclasses MsgBasedTCPClient, and wraps an ECDHSession instance.
    All the messages are delivered to ECDHSession.
    """
    def __init__(self, addr="localhost",port=55755):
        """
        Creates a new instance of super (MsgBasedTCPClient), connects it to the
        given endpoint, then calls ecdh_init(...) and starts negotiating a key with
        the recipient.

        Input:
            addr        The address where to connect the socket, default "localhost"
            port        The port where to connect, default 55755
        """
        try:
            super(ECDHClient, self).__init__(addr=addr,port=port)
            self._session=ECDHSession(self.sendMessage)
            self._session.initECDH()
        except Exception, e:
            # print it to stdout, then raise it
            log(LOG_ERROR, "ecdh(init): "+str(e))
            raise e

    def sendEncryptedMessage(self, msg):
        """
        Same as ECDHSession.sendEncryptedMessage(...). See reference.
        """
        self._session.sendEncryptedMessage(msg)

    def messageReceived(self, msg):
        return self._session.messageReceived(msg)


class ECDHServer(MsgBasedTCPServer):
    """
    Subclasses MsgBasedTCPServer and wraps an ECDHSession instance.
    All the messages are delivered to ECDHSession.
    """
    def __init__(self, addr="localhost", port=55755):
        """
        Creates a new instance of super (MsgBasedTCPServer) and puts it in listening mode.

        Input:
            addr        The address where to connect the socket, default "localhost"
            port        The port where to connect, default 55755
        """
        try:
            super(ECDHServer, self).__init__(addr=addr, port=port)
            self._session=ECDHSession(self.sendMessage)
        except Exception, e:
            # print it to stdout, then raise it
            log(LOG_ERROR, "ecdh(init): "+str(e))
            raise e

    def sendEncryptedMessage(self, msg):
        """
        Same as ECDHSession.sendEncryptedMessage(...). See reference.
        """
        self._session.sendEncryptedMessage(msg)

    def messageReceived(self, msg):
        return self._session.messageReceived(msg)   
