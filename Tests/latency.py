#!/usr/bin/env python3
import time
import socket
import struct
import random
import argparse

FILECACHE_CMD_READ  = 0
FILECACHE_CMD_LOAD  = 1
KEY                 = 0xb737fb1a
POS                 = 1
SIZE                = 1024
PORT                = 6666
RAND                = 0xdeadbeef

def main(args):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  message = struct.pack('HILII', FILECACHE_CMD_LOAD, KEY, POS, SIZE, RAND)
  s.sendto(message, (args.ip, PORT))
  print(s.recvfrom(4))
  time.sleep(2)
  message = struct.pack('HILIII', FILECACHE_CMD_READ, KEY, POS, SIZE, RAND, 0)
  s.sendto(message, (args.ip, PORT))
  print(s.recvfrom(0x100))

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Perform latency test")
  parser.add_argument("ip", help="The target IP address to perform the test on")
  args = parser.parse_args()
  main(args)
