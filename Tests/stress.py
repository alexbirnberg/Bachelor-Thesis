#!/usr/bin/env python3
import time
import socket
import struct
import argparse
import threading

FILECACHE_CMD_READ  = 0
FILECACHE_CMD_LOAD  = 1
KEY                 = 0xb737fb1a
POS                 = 0
SIZE                = 1024
PORT                = 6666
RAND                = 0xdeadbeef

def stress():
  message = struct.pack('<HIQIII', FILECACHE_CMD_READ, KEY, POS, SIZE, RAND, 0)
  while True:
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.sendto(message, (args.ip, PORT))
      s.close()
    except:
      pass

def main(args):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  # Load file contents in memory
  message = struct.pack('<HIQII', FILECACHE_CMD_LOAD, KEY, POS, SIZE, RAND)
  s.sendto(message, (args.ip, PORT))
  s.recvfrom(4)
  s.close()

  for i in range(100):
    thread = threading.Thread(target=stress)
    thread.start()
  thread.join()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Perform latency test")
  parser.add_argument("ip", help="The target IP address to perform the test on")
  args = parser.parse_args()
  main(args)
