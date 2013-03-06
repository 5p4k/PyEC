"""
netcomm module - Message-based over sockets client and server

netcomm provides two objects wrapping sockets, threads, listening sockets with the
purpose of setting up a simple connection where you can send and receive messages.
There is also a simple function that displays an interactive dialog to the user
to set up a connection; if the module getnifs_mac/linux is available, in the
interactive dialog displays the list of network interfaces where to listen at.

Uses logging.log.
"""
import socket
import threading
import SocketServer
import base64
from logging import *

class MsgBasedTCPClient(object):
    """
    This class wraps a socket and a listening thread. Connects the socket to
    the remote address and starts listening asynchronously; use sendMessage(...)
    to send a message, and the method messageReceived gets called every time
    the listening thread receives a message.

    A "message" is any sequence of data; to be trasmitted, messages are encoded
    with base64 and newline-terminated.

    This class isn't thread-safe, and includes an uncomfortable and disorganic
    form of logging (a description is printed out in case of errors that shouldn't
    halt the execution, the others aren't even caught; some other operations
    are logged too).
    """

    def __init__(self,addr="localhost",port=55755):
        """
        Sets up a socket at the desired host and port and connects it. Then
        the listening thread is created and run.

        Input:
            addr        The address where to connect the socket, default "localhost"
            port        The port where to connect, default 55755

        Remarks:
            No exception handling is performed: the exceptions raised by
            socket.socket(...) and socket.connect(...) are passed straight to the
            caller.
        """
        super(MsgBasedTCPClient, self).__init__()

        log(LOG_INFO, "net", "starting listening thread")
        self._keepListening=True
        self._listeningThread=threading.Thread(target=self._listen)
        self._listeningThread.daemon=True
        
        log(LOG_INFO, "net", "connecting to {}:{}".format(addr, port))
        self._socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((addr, port))
        self._socket.settimeout(1.)

        self._listeningThread.start()
    

    def sendMessage(self, msg):
        """
        Encodes and sends a string to the recepient.

        Input:
            msg         The string to be sent

        Output:
            Boolean, false in case of failure.

        Remarks:
            if socket.sendall(...) fails, the reason is printed to stdout.
        """
        # encode the message
        msg=base64.b64encode(msg)+"\n"
        try:
            self._socket.sendall(msg)
            return True
        except Exception, e:
            log(LOG_ERROR, "net(send): "+str(e))
            return False

    def messageReceived(self, msg):
        """
        Invoked when a new message is received. Default implementation simply prints
        msg. Returning False from this method causes the listening to stop: use this
        feature to implement behaviours such as a "disconnect" command.

        Input:
            msg         Decoded message.

        Output:
            Boolean, False will cause the listening thread to abort.
        """
        log(LOG_INCOMING, "net", ""+msg)
        return True

    def stopListening(self):
        """
        Use this method to stop the listening thread.

        Remarks:
            The listening thread reads from socket, but has a timeout of 1 second;
            therefore, the thread is expected to join in about 1 second.
        """

        log(LOG_INFO, "net", "stopping listener thread")
        self._keepListening=False


    def _listen(self):
        log(LOG_INFO, "net", "listening thread started")

        data=""

        while self._keepListening:
            try:
                buffer=self._socket.recv(1024)
            except Exception, e:
                # check if it's a timeout
                if isinstance(e, socket.timeout):
                    continue
                
                # some real error
                log(LOG_ERROR, "net(recv): "+str(e))
                break
            

            # search for "\n"
            index=buffer.find("\n")
            while index>-1:
                # append to data
                data+=buffer[:index]

                # decode and process message
                try:
                    msg=base64.b64decode(data)
                    if not self.messageReceived(msg):
                        try:
                            self._socket.shutdown(SHUT_RDWR)
                        finally:
                            break
                except Exception, e: #malformed string
                    log(LOG_WARNING, "net(recv): "+str(e))

                # data has been processed, trash it
                data=""

                # next
                buffer=buffer[(index+len("\n")):]
                index=buffer.find("\n")

            # enqueue
            data+=buffer

        log(LOG_INFO, "net", "listener thread halted")

    def __del__(self):
        self._keepListening=False
        self._socket.close()



class MsgBasedTCPServerHandler(SocketServer.BaseRequestHandler):
    """
    This class inherits from BaseRequestHandler and provides all the routines needed
    to implement a message-based behaviour in the server too, as in MsgBasedTCPClient;
    actually many methods are identical.
    This is not intended to be used outside MsgBasedTCPServer implementation.
    """

    def setup(self):
        self._keepListening=True
        self.request.settimeout(1.)
        
    def stopListening(self):
        log(LOG_INFO, "net", "stopping serving request")
        self._keepListening=False

    def handle(self):
        # check if the server is already serving a session
        if self.server._servingInstance==None:
            self.server._servingInstance=self
        else:
            return

        # expects a single message in base64 format
        # terminated by a "\n"
        log(LOG_INFO, "net", "incoming connection from "+str(self.client_address))

        data=""

        while self._keepListening:
            try:
                buffer=self.request.recv(1024)
            except Exception, e:
                # check if it's a timeout
                if isinstance(e, socket.timeout):
                    continue
                
                # some real error
                log(LOG_ERROR, "net(recv): "+str(e))
                break
            

            # search for "\n"
            index=buffer.find("\n")
            while index>-1:
                # append to data
                data+=buffer[:index]

                # decode and process message
                try:
                    msg=base64.b64decode(data)

                    if not self.server.messageReceived(msg):
                        try:
                            self.request.shutdown(SHUT_RDWR)
                        finally:
                            break
                except Exception, e: #malformed string
                    log(LOG_WARNING, "net(recv): "+str(e))


                # data has been processed, trash it
                data=""

                # next
                buffer=buffer[(index+len("\n")):]
                index=buffer.find("\n")

            # enqueue
            data+=buffer

        self.server._servingInstance=None

        log(LOG_INFO, "net", "stopped serving request")

    def finish(self):
        self.request.close()

class MsgBasedTCPServer(object, SocketServer.TCPServer):
    """
    This class wraps a listening socket; use sendMessage(...) to send a message, and
    the method messageReceived gets called every time a message is received.

    A "message" is any sequence of data; to be trasmitted, messages are encoded
    with base64 and newline-terminated.

    This class isn't thread-safe, and includes an uncomfortable and disorganic
    form of logging (a description is printed out in case of errors that shouldn't
    halt the execution, the others aren't even caught; some other operations
    are logged too).
    """
    def __init__(self, addr="localhost", port=55755):
        """
        Sets up a socket at the desired host and port and starts listening on another
        thread.

        Input:
            addr        The address where to connect the socket, default "localhost"
            port        The port where to connect, default 55755
        """
        super(MsgBasedTCPServer, self).__init__()

        self._servingInstance=None
        self._listeningThread=threading.Thread(target=self._invokeListen)
        self._listeningThread.daemon=True
        
        SocketServer.TCPServer.__init__(self, (addr, port), MsgBasedTCPServerHandler)
        self._listeningThread.start()

    def _invokeListen(self):
        # SocketServer.TCPServer.serve_forever(self)
        # handle only one request
        SocketServer.TCPServer.handle_request(self)

    def stopListening(self):
        """
        Use this method to discard a current request being handled.

        Remarks:
            The listening routine reads from socket, but has a timeout of 1 second;
            therefore, the request is expected to be discarded in 1 second.
        """
        if self._servingInstance!=None:
            self._servingInstance.stopListening()

    def messageReceived(self, msg):
        """
        Invoked when a new message is received. Default implementation simply prints
        msg. Returning False from this method causes the request to be discarded;
        use this feature to implement behaviours such as a "disconnect" command.

        Input:
            msg         Decoded message.

        Output:
            Boolean, False will cause the request being handled to be discarded.
        """
        log(LOG_INCOMING, "net", ""+msg)
        return True

    def sendMessage(self, msg):
        """
        Encodes and sends a string to the recepient.

        Input:
            msg         The string to be sent

        Output:
            Boolean, false in case of failure.

        Remarks:
            if socket.sendall(...) fails, the reason is printed to stdout.
        """
        if self._servingInstance==None:
            return
        # encode the message
        msg=base64.b64encode(msg)+"\n"
        try:
            self._servingInstance.request.sendall(msg)
        except Exception, e:
            log(LOG_ERROR, "net(send): "+str(e))

    def __del__(self):
        self.stopListening()
        SocketServer.TCPServer.shutdown(self)




def runConnectOrListen(clientClass=MsgBasedTCPClient, serverClass=MsgBasedTCPServer):
    """
    Runs an interactive dialog and returns a client or server instance.

    Input:
        clientClass     Defaults to MsgBasedTCPClient.
        serverClass     Defaults to MsgBasedTCPServer.

        Client and server classes are intended to be subclasses of the defaults; actually
        it's enough if they provide a __init__(addr=xyz) method.

    Output:
        An instance of clientClass or serverClass.

    Remarks:
        The dialog is like this:

            >>> connect or listen? connect
            >>> ip address (empty=>localhost)? 192.168.1.1
            
        and the constructor invoked is clientClass(addr=xyz), where xys==192.168.1.1 in the
        example. If left empty, still addr=="localhost" is given to clientClass as argument.
        As it regards listening,

            >>> connect or listen? listen
            ... wait for an incoming connection before typing!

        or, on Unix and Mac OS systems where getnifs works,

            >>> connect or listen? listen
            >>> choose one of the network interfaces to bind (empty=>loopback l0):
                en1     192.168.1.24
                lo0     127.0.0.1
            >>> en1
            ... ready to listen at 192.168.1.24 on en1
            ... wait for an incoming connection before typing!

        The interfaces displayed are only those that have a valid ip address associated with.
        If available, IPv4 is displayed (for readability), otherwise IPv6 is used.
        If an interface with 127.0.0.1 or localhost as address is found, then the dialog
        gives also the default option empty=>loopback xyz.
        If no interface is found matching these criteria, the server is created simply
        with clientClass(), otherwise clientClass(addr=chosenInterfaceAddr).

    """
    channel=None
    while channel==None:
        input=raw_input(">>> connect or listen? ")
        if input=="connect":
            addr=raw_input(">>> ip address (empty=>localhost)? ")
            if len(addr)==0: addr="localhost"
            channel=clientClass(addr=addr)
        elif input=="listen":
            import platform
            osname=platform.system().lower()
            netifaces=None
            try:
                if osname=="darwin":
                    import support.getnifs_mac as getnifs
                    netifaces=getnifs.get_network_interfaces()
                elif osname=="linux":
                    import support.getnifs_linux as getnifs
                    netifaces=getnifs.get_network_interfaces()
            finally:
                pass
            
            interfaces={}
            if netifaces!=None:
                # create a dictionary interface->addr
                loopback=None
                for interface in netifaces:
                    addr=interface.addresses.get(socket.AF_INET)
                    if addr==None: addr=interface.addresses.get(socket.AF_INET6)
                    if addr==None: continue

                    if addr=="127.0.0.1" or addr=="localhost":
                        loopback=interface.name

                    #ok store this
                    interfaces[interface.name]=addr

            if len(interfaces)>0:
                chosen=""
                while interfaces.get(chosen)==None:
                    # print all the available interfaces
                    if loopback!=None:
                        print(">>> choose one of the network interfaces to bind (empty=>loopback {}):".format(loopback))
                    else:
                        print(">>> choose one of the network interfaces to bind:")
                    for name in interfaces:
                        print("\t{}\t{}".format(name, interfaces[name]))

                    chosen=raw_input(">>> ")
                    if len(chosen)==0 and loopback!=None:
                        chosen=loopback

                log(LOG_INFO, "ready to listen at {} on {}".format(chosen, interfaces.get(chosen)))
                # start listening on that!
                channel=serverClass(addr=interfaces.get(chosen))
            else:
                channel=serverClass()

            log(LOG_INFO, "wait for an incoming connection before typing!")

    return channel

if __name__ == "__main__":
    channel=runConnectOrListen()
    input=raw_input()
    while len(input)>0:
        channel.sendMessage(input)
        input=raw_input()

    channel.stopListening()