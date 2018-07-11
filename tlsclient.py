import ssl
import socket
import threading
import time
import pdb

class _LockedObject:

    def __init__(self, obj = None):
        self.obj = obj
        self.lock = threading.Lock()

class _SocketReceivingThread(threading.Thread):

    def __init__(self, socket, receiver):
        threading.Thread.__init__(self)
        self.__socket = socket
        self.__receiver = receiver

    def run(self):
        while True:
            with self.__socket.lock:
                result = self.__socket.obj.recv(4096)
                if len(result) == 0:
                    self.__socket.obj.close()
                    self.__socket.obj = None
                    return
            self.__receiver(result)

class _SocketWrapper:

    def __init__(self, destination, receiver):
        self._destination = destination
        
        # although socket itself is thread safe, what we are
        # actually using here is a Nullable<Socket>. Hence we need
        # a lock to make sure while one thread is operating on
        # the socket object, there won't be another thread comes
        # in and make it None

        self._socket = _LockedObject()    
        self._thread = None
        self._receiver = receiver

    def send(self, blob):
        """
        send the specified 'blob'. This method should be called on the plain2tls thread only.
        """
        with self._socket.lock:
            if self._socket.obj != None:
                try:
                    self._socket.obj.send(blob)
                    # Normal exit
                    return
                except:
                    # socket has closed, fall through to socket restart process
                    pass
        
        if self._thread != None:
            thread = self._thread
            self._thread = None
            thread.join()
            
        with self._socket.lock:
            # By design, there should be only one thread that creates socket, i.e.
            # we don't need to worry about another thread coming in and create the socket
            # in between previous lock release and this lock acquire. Therefore, no
            # double checing here.
             
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.obj = ssl.wrap_socket(tcp_socket, ssl_version = ssl.PROTOCOL_SSLv23)
            self._socket.obj.setblocking(True)
            self._socket.obj.connect(self._destination)
            self._socket.obj.send(bytes(blob))
            self._thread = _SocketReceivingThread(self._socket, self._receiver)
            self._thread.start()

    def close(self):
        """
        close must be called from plain2tls thread
        """
        if self._thread != None:
            self._thread.join()
            self._thread = None

class TLSClient:
    """
    a DNS over TLS client
    """

    def __init__(self, destination, callback, dispatcher):
        """
        create a DNS over TLS client. Remote server is specified by the 'destination' tuple: (host, port).
        Use the specified 'dispatcher' to invoke response callback on tls2plain thread
        """

        # readonly
        self._callback = callback

        # the outstanding map is shared between plain2tls and tls2plain thread, therfore
        # we need a lock here
        self._outstanding = _LockedObject({})
        
        # plain2tls thread only
        self._currentId = 1
        self._wrapped_socket = _SocketWrapper(destination, dispatcher(self._receive_data))

        # tsl2plain thread only
        self._buffer = []

    def _receive_data(self, blob):
        """
        This method can only be called on the tls2plain thread. Receive data and try to
        assemble the response, invoke callback if a full response has been received
        """
        self._buffer.extend(blob)

        buffer_size = len(self._buffer)

        if buffer_size <= 4:
            return

        length = self._buffer[0] * 0x100 + self._buffer[1]
        if buffer_size < length + 2:
            return

        responseId = self._buffer[2] * 0x100 + self._buffer[3]
        response = self._buffer[4 : length + 2]
        remaining = self._buffer[length + 2 : ]

        self._buffer.clear()
        self._buffer.extend(remaining)

        with self._outstanding.lock:
            correlator = self._outstanding.obj.pop(responseId)
        
        assert correlator != None
        self._callback(correlator, response)

    def send(self, correlator, query):
        """
        send the specified 'query', invoke the specified 'callback' when response is received.
        This method must be called on the plain2tls thread, while 'callback' will be invoked
        on the tls2plain thread
        """

        with self._outstanding.lock:

            # get next available id
            while (self._currentId in self._outstanding.obj):
                self._currentId = self._currentId + 1
                if self._currentId == 0x10000:
                    self._currentId = 1

            # Associate query id with correlator, so that when response carrying the same id
            # is received, we can match the response to the correct correlator 
            self._outstanding.obj[self._currentId] = correlator

        # build the packet and send
        length = len(query) + 2
        data = [ length // 0x100, length % 0x100,
                 self._currentId // 0x100, self._currentId % 0x100 ]
        
        data.extend(query)

        self._wrapped_socket.send(data)

    def close(self):
        """
        Must be called from plain2tls thread
        """
        self._wrapped_socket.close()
