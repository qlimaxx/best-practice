import socket

from crypto import CryptoBox


class Client(CryptoBox):

    def __init__(self):
        CryptoBox.__init__(self)
        self.sock = None
       
    def connect(self, host, port, timeout=None):
        try:
            socket.setdefaulttimeout(timeout) 
            self.sock = socket.create_connection((host, port),
                                                  timeout)
            if self.sock is None:
                return False
            else:
                self.sock.settimeout(timeout)
                return True
        except:
            return False

    def sendall(self, buffer, nbytes=0):
        nb = 0
        if nbytes == 0:
            nbytes = len(buffer)
        while nb < nbytes:
            nb += self.sock.send(buffer[nb:nbytes])
        return nb
            

    def recvall(self, nbytes):
        nb = 0
        buffer = ''
        tmp_buffer = ''
        while nb < nbytes:
            tmp_buffer = self.sock.recv(1024)
            buffer += tmp_buffer
            nb += len(tmp_buffer)
        return buffer[:nbytes]                  
        
    def close(self):
        self.sock.close()
