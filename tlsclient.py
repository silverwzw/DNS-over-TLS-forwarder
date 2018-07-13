import config
import util

import ssl
import socket
import threading
import queue

_TERMINATE = "TLS_THREAD_DO_TERMINATE"

def _wait_for_queries(query_queue):

    query = query_queue.get(block = True)
    if query == _TERMINATE:
        return [], True

    queries = [ query ]
    terminate = False
    while len(queries) < config.MAX_NUM_QUERY_PER_CONNECTION and not query_queue.empty():
        try:
            query = query_queue.get(block = False)
        except queue.Empty:
            break
        if query == _TERMINATE:
            terminate = True
            break
        queries.append(query)

    return queries, terminate

def _assemble_payload(queries):

    index_to_cb_map = {}
    payload = []
    
    for index, (query, cb) in enumerate(queries):
        index_to_cb_map[index] = cb
        size = 2 + len(query)
        payload.extend([ size  // 0x100, size  % 0x100,
                         index // 0x100, index % 0x100,
                         *query ])
    
    return payload, index_to_cb_map


def _send_payload_and_wait(context, destination, payload):
    
    context.socket.setblocking(True)
    context.socket.connect(destination)
    context.socket.send(bytes(payload))

    while not context.closed:
        try:
            blob = context.socket.recv(config.TLS_SOCKET_BUFER_SIZE)
        except:
            break
        if len(blob) == 0:
            break
        yield from blob

def _disassemble_payload(payload):

    while True:
        size  = next(payload) * 0x100 + next(payload) - 2
        index = next(payload) * 0x100 + next(payload)
        response = [ next(payload) for _ in range(size) ]
        yield (index, response)

def _notify(context, responses, cb_map):
    try:
        while len(cb_map) > 0:
            index, response = next(responses)
            callback, dispatcher = cb_map[index]
            del cb_map[index]
            if dispatcher == None:
                callback(response)
            else:
                dispatcher.dispatch(callback, response)
    finally:
        context.closed = True
        context.socket.close()

class _SocketContext:
    def __init__(self):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = ssl.wrap_socket(tcp_socket, ssl_version = ssl.PROTOCOL_SSLv23)
        self.closed = False

class _RequestThread(threading.Thread):

    def __init__(self, query_queue, destination):
        threading.Thread.__init__(self)
        self.__queue = query_queue
        self.__destination = destination

    def run(self):
        
        terminate = False

        while not terminate:

            queries, terminate = _wait_for_queries(self.__queue)
            if len(queries) == 0:
                continue
            request_payload, cb_map = _assemble_payload(queries)
            context = _SocketContext()
            response_payload = _send_payload_and_wait(context, self.__destination, request_payload)
            responses = _disassemble_payload(response_payload)
            _notify(context, responses, cb_map)

            for _ in queries:
                self.__queue.task_done()
        
        # also mark terminate task as done
        self.__queue.task_done()

class TLSClient:

    def __init__(self, destination, dispatcher = None, num_thread = config.MAX_NUM_TLS_CONNECTION):
        self.__dispatcher = dispatcher
        self.__queue = queue.Queue()
        self.__started = False
        self.__closed = False
        self.__threadPool = [ _RequestThread(self.__queue, destination) for _ in range(num_thread) ]

    def start(self):
        if self.__started:
            raise Exception("TLS client already started")
        for thread in self.__threadPool:
            thread.start()
        self.__started = True

    def query(self, blob, callback):

        if not self.__started:
            raise Exception("Cannot query before TLS client is started")
        if self.__closed:
            raise Exception("TLS client already closed")
        
        cb = (callback, self.__dispatcher)
        self.__queue.put((blob, cb), block = False)

    def close_wait_queued(self):

        if not self.__started:
            raise Exception("Cannot close TLS client before started")

        self.__closed = True
        self.__queue.join()

        for thread in self.__threadPool:
            self.__queue.put(_TERMINATE, block = False)
        for thread in self.__threadPool:
            thread.join()

    def close_wait_sent(self):

        if not self.__started:
            raise Exception("Cannot close TLS client before started")

        self.__closed = True

        for thread in self.__threadPool:
            thread.close()
        for thread in self.__threadPool:
            thread.join()
        
        while not self.__queue.empty():
            try:
                query, (callback, dispatcher) = self.__queue.get(block = False)
                error_response = util.error_blob(query, util.ERROR_SERVER)
                if dispatcher == None:
                    callback(error_response)
                else:
                    dispatcher.dispatch(callback, error_response)
                self.__queue.task_done()
            except:
                pass