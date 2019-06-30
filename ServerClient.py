#! /usr/bin/python
#
# ServerClient.py - 2-way Chat Server with textbook/oaep RSA-AES encryption.
#                   Cracker is able to crack the AES session key through CCA2 method.
#
# Shiyi Cao 2019.6.30


import sys
import socket
import threading
import RSA
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex
import random

def main():
    """
    Main - Checks for correct input arguments and runs the appropriate methods
    """

    if len(sys.argv) < 4:
        print('Usage: python ServerClient.py <server|client|crack> <port> <algorithm>\n')
        return -1
    else:
        alg = 0
        if sys.argv[3].lower() == 'oaep':
            alg = 1
        elif sys.argv[3].lower() == 'rsa':
            alg = 0

        if sys.argv[1].lower() == 'server':
            Server(sys.argv[2], alg)
        elif sys.argv[1].lower() == 'client':
            Client(sys.argv[2], alg)
        elif sys.argv[1].lower() == 'cracker':
            Cracker(sys.argv[2], alg)
        else:
            print('Unrecognized argument: ', sys.argv[1])
            return -1
    return 0


def Server(port, algorithm):
    """
    Creates the server instance, sets it up
    """
    host = 'localhost'
    port = int(port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    # blocking call to accept()
    print('Waiting for partner to join conversation...\n')
    (conn, client_addr) = server.accept()
    print('Client connected: ', client_addr[0])

    # Geberate public-private key pair
    e, d, n = RSA.generateKey()
    sendPublic = str(e) + ',' + str(n)
    conn.send(sendPublic.encode('utf-8'))
    print('Public Key sent')
    privateTuple = (d, n)

    # Verify WUP Request
    flag = 0
    count = 1
    while count != 129:
        # Decrypt Session Key and WUP request
        print('Number of Trials:', count)

        wup_enc = conn.recv(128)
        encrypted_skey = int(conn.recv(1024).decode('utf-8'))
        print(wup_enc)
        print(len(wup_enc))

        skey = bin(RSA.fastExpMod(encrypted_skey, privateTuple[0], privateTuple[1]))[-128:]
        skey = int(skey, 2)
        string = ""
        for i in hex(skey)[2:]:
            string += i
        add = 32 - len(string)
        string = '0' * add + string
        print('Session Key is:', string)
        #wup2 = str(AES.new(a2b_hex(hex(skey)[2:]), AES.MODE_ECB).decrypt(wup_enc), 'utf-8')
        wup = AES.new(a2b_hex(string), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(wup_enc), 'utf-8')))
        print('WUP Request is:', wup)
        if verify_wup(wup):
            response = "Valid wup format"
            print('Wup Verified')
            flag = 1
        else:
            response = "xxxxxxxxxxxxxxxx"
            print('Invalid wup format')
            flag = 0
        enc_response = AES.new(a2b_hex(string), AES.MODE_ECB).encrypt(response)
        print("Encrypted Response:", enc_response)
        conn.send(enc_response)
        count = count + 1

    print('Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n')

    ReadThread = Thread_Manager('read', conn, a2b_hex(hex(skey)[2:]))
    WriteThread = Thread_Manager('write', conn, a2b_hex(hex(skey)[2:]))

    ReadThread.start()
    WriteThread.start()

    # wait until client dc's
    ReadThread.join()
    print('Your partner has left the conversation. Press any key to continue...\n')

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except:
        # connection already closed
        pass

    # shut down server
    print('Shutting server down...')
    server.shutdown(socket.SHUT_RDWR)
    server.close()

    return 0


def Client(port, algorithm):
    """
    Creates the client instance, sets up the client
    """

    host = 'localhost'
    port = int(port)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Receive Server's Public Key
    key = client.recv(2048).decode('utf-8')
    key = key.split(',')
    keyTuple = (int(key[0]), int(key[1]))
    print('Server\'s Public Key received:', keyTuple)

    wup_request = "network_security"
    skey = 0
    while skey % 2 == 0:
        skey = random.randrange(1 << 127, 2 ** 128)
    enc_skey = RSA.endecrypt(skey, keyTuple[0], keyTuple[1])


    for i in range(128, 0, -1):
        print('Number of trials:', 129 - i)

        # Send Encrypted Session Key and WUP Request
        encrypted_wup = AES.new(a2b_hex(hex(skey)[2:]), AES.MODE_ECB).encrypt(wup_request)

        send_content1 = encrypted_wup
        send_content2 = str(enc_skey)

        client.send(send_content1)
        print('Encrypted Wup Sent:', encrypted_wup)
        client.send(send_content2.encode('utf-8'))
        print('Session Key Sent:', send_content2)

        response_enc = client.recv(1024)
        response = AES.new(a2b_hex(hex(skey)[2:]), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(response_enc), 'utf-8')))

        print('Response:', response)


    print('Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n')
    ReadThread = Thread_Manager('read', client, a2b_hex(hex(skey)[2:]))
    WriteThread = Thread_Manager('write', client, a2b_hex(hex(skey)[2:]))

    ReadThread.start()
    WriteThread.start()

    ReadThread.join()
    print('Your partner has left the conversation. Press any key to continue...\n')

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        client.shutdown(socket.SHUT_RDWR)
        client.close()
    except:
        # connection already killed
        pass


def Cracker(port, algorithm):
    """
    Creates the cracker instance, sets up the cracker
    """

    host = 'localhost'
    port = int(port)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    # Receive Server's Public Key
    key = client.recv(2048).decode('utf-8')
    key = key.split(',')
    keyTuple = (int(key[0]), int(key[1]))
    print('Server\'s Public Key received:', keyTuple)

    wup_request = "network_security"
    skey = 0
    while skey % 2 == 0:
        skey = random.randrange(1 << 127, 2 ** 128)
    enc_skey = RSA.endecrypt(skey, keyTuple[0], keyTuple[1])

    # Start Cracking
    cur_skey = 0
    for i in range(128, 0, -1):
        print('Number of trials:', 129 - i)

        # Send Encrypted Session Key and WUP Request
        cur_skey_test = int(cur_skey >> 1) + (1 << 127)
        print("k" + str(i - 1), ": ", bin(cur_skey_test)[2:])
        fac = RSA.fastExpMod(2, (i - 1) * keyTuple[0], keyTuple[1])
        enc_cur_skey_test = RSA.fastExpMod(enc_skey * fac, 1, keyTuple[1])
        encrypted_wup = AES.new(a2b_hex(hex(cur_skey_test)[2:]), AES.MODE_ECB).encrypt(wup_request)

        send_content1 = encrypted_wup
        send_content2 = str(enc_cur_skey_test)

        client.send(send_content1)
        print('Encrypted Wup Sent:', encrypted_wup)
        client.send(send_content2.encode('utf-8'))
        print('Session Key Sent:', send_content2)

        # Get response from the server
        response_enc = client.recv(1024)
        response = AES.new(a2b_hex(hex(cur_skey_test)[2:]), AES.MODE_ECB).decrypt(a2b_hex(str(b2a_hex(response_enc), 'utf-8')))

        print('Response:', response)
        if response == b"Valid wup format":
            cur_skey = cur_skey_test
        else:
            cur_skey_test = int(cur_skey >> 1)
            cur_skey = cur_skey_test

    if skey == cur_skey:
        print('Successfully cracked.')
    else:
        print('Crack failed.')

    print('True Session Key:', skey)
    print('Cracked Session Key:', cur_skey)


    print('Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n')
    ReadThread = Thread_Manager('read', client, a2b_hex(hex(skey)[2:]))
    WriteThread = Thread_Manager('write', client, a2b_hex(hex(skey)[2:]))

    ReadThread.start()
    WriteThread.start()

    ReadThread.join()
    print('Your partner has left the conversation. Press any key to continue...\n')

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        client.shutdown(socket.SHUT_RDWR)
        client.close()
    except:
        # connection already killed
        pass


def verify_wup(wup):
    return wup == b"network_security"


class Thread_Manager(threading.Thread):
    """
    Creates threads for asynchronoues reading and writing
    """

    def __init__(self, action, conn, skey):
        """
        Constructor for Thread_Manager class
        """

        threading.Thread.__init__(self)
        self.action = action.lower()
        self.conn = conn
        self.dowrite = True
        self.exitcode = 'EXIT'
        self.skey = skey

    def run(self):
        """
        Invoked when new thread is executed
        """

        if (self.action == 'read'):
            self.read()
        else:
            self.write()

    def stopWrite(self):
        """
        Terminates the write loop
        """

        self.dowrite = False

    def decrypt(self, buff):
        """
        Decrypts input integer list into sentences
        """

        decrypted_data = AES.new(self.skey, AES.MODE_ECB).decrypt(buff)
        return decrypted_data

    def read(self):
        """
        Responsible for reading in data from the client and displaying stdout
        """

        buff = self.conn.recv(1024)
        buff = self.decrypt(buff)
        while buff.strip() != self.exitcode and len(buff) > 0:
            print('Message received: ', buff.strip())
            buff = self.conn.recv(1024)
            buff = self.decrypt(buff)
        # client disconnected
        self.stopWrite()

    def encrypt(self, data):
        encrypted_data = AES.new(self.skey, AES.MODE_ECB).encrypt(data)
        return encrypted_data

    def write(self):
        """
        Responsible for reading in data from stdin and sending to client
        """

        while self.dowrite:
            data = sys.stdin.readline()
            if (data.strip() == self.exitcode):
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.dowrite = False
            else:
                print(len(data.strip()))
                length = len(data.strip())
                if length % 16 != 0:
                    pad = 16 - (length % 16)
                else:
                    pad = 0
                data = data.strip() + ('\0' * pad)
                data = self.encrypt(data)
                self.conn.send(data)


# Entry point
if __name__ == "__main__":
    sys.exit(main())
