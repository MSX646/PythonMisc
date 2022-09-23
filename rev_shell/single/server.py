#!/usr/bin/env python
import signal
import socket
import sys
import threading
from queue import Queue

NUM_THREADS = 2
JOB = [1, 2]
queue = Queue()
all_conn = []
all_addrs = []



def sig_quit(signal=None, frame=None):
    print('\nQuitting...')
    if sock:
        try:
            sock.shutdown(2)
            sock.close()
        except Exception as e:
            print('Could not close connection %s' % str(e))
            # continue
    sys.exit(0)
    return


def sock_create():
    try:
        global host
        global port
        global sock

        host = ''
        port = int(sys.argv[1])
        sock = socket.socket()
    except (socket.error, ValueError) as msg:
        print(str(msg))
        sys.exit(1)

def sock_bind():
    try:
        global host
        global port
        global sock

        print("Listening...[{}]".format(port))
        sock.bind((host, port))
        sock.listen(5)
    except (socket.error, OverflowError) as msg:
        print("Failed to bind: " + str(msg))
        sys.exit(1)
        #sock_bind()

def socket_accept():
    conn, addr = sock.accept()
    print("Connection established -> {}:{}".format(addr[0], addr[1]))
    send_cmd(conn)
    conn.close()

def send_cmd(conn):
    while True:
        cmd = input()
        if cmd == 'quit':
            conn.close()
            sock.close()
            sys.exit()
        if len(str.encode(cmd)) > 0:
            conn.send(str.encode(cmd))
            client_res = str(conn.recv(4096), 'utf-8')
            print(client_res, end="")


def main():
    if len(sys.argv) < 2:
        print("Usage: ./server.py <port>")
        sys.exit(1)

    signal.signal(signal.SIGINT, sig_quit)
    signal.signal(signal.SIGTERM, sig_quit)
    
    sock_create()
    sock_bind()
    socket_accept()


if __name__ == "__main__":
    main()
