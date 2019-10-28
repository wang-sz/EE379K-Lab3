#!/usr/bin/env python3
# fuzzer for vulnserver
import socket
import os
import sys
import select
import string
import random
import time

CMDS = ["STATS", "RTIME", "LTIME", "SRUN", "TRUN", "GMON", "GDOG", "KSTET", "GTER", "HTER", "LTER", "KSTAN"]

def vuln(cmd):
  for i in range(100, 10000, 100):
    payload = cmd + " " + ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(i))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      sock.connect(("10.0.2.4", 9999))
    except socket.error as e:
      print("ERROR: cannot connect: {}".format(e.message))
      return i, payload

    sock.setblocking(0)
    ready = select.select([sock], [], [], 5)

    if not ready[0]:
      return i, payload

    data = sock.recv(1024)
    print("received: {}".format(data)) # server connection response

    print("sending malicious with {} bytes".format(len(payload)))
    sock.send(payload.encode())

    sock.setblocking(0)
    ready = select.select([sock], [], [], 5)

    time.sleep(0.1)
    if not ready[0]:
      return i, payload

    data = sock.recv(1024)
    print("received: {}".format(data))
  return 0, payload

if __name__ == "__main__":
  vuln_cmd = []
  for cmd in CMDS:
    size, payload = vuln(cmd)
    if size != 0:
      print("possibly vulnerable cmd: {}".format(cmd))
      vuln_cmd.append({"cmd":cmd, "size":size, "payload":payload})
      input("Restart server then press any key to continue")
    else:
      print("safe cmd: {}".format(cmd))
  print("\nALL VULN CMDS")
  for cmd in vuln_cmd:
    print("{} - {}".format(cmd['cmd'], cmd['size']))
