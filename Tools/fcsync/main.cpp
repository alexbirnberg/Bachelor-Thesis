#include <string>
#include <iostream>
#include <unistd.h>

#include "fcsync.hpp"
#include "cache.hpp"
#include "client.hpp"

void do_help() {
  fprintf(stderr,
		"Usage: fcsync COMMAND [OPTIONS]\n"
		"\n"
		"       COMMAND := { add | del | get }\n"
		"\n");
}

void do_add_help() {
  fprintf(stderr,
		"Usage: fcsync add BLOCK_DEVICE FILE_PATH\n"
		"\n"
		"Example: fcsync add /dev/sda1 /home/user/Public/Photos.zip\n"
		"\n");
}

void do_del_help() {
  fprintf(stderr,
		"Usage: fcsync del KEY\n"
		"\n"
		"Example: fcsync del 0x8ec1f1de\n"
		"\n");
}

void do_get_help() {
  fprintf(stderr,
		"Usage: fcsync get HOST KEY\n"
		"\n"
		"Example: fcsync get 10.0.0.3 0x8ec1f1de 0x1000\n"
		"\n");
}

int do_add(int argc, char **argv) {
  int ret = -1;
  std::string bdev, path;
  
  if (argc < 4) {
    do_add_help();
    goto end;
  }
  bdev = argv[2];
  path = argv[3];

  ret = fcsync_add(bdev, path);
end:
  return ret;
}

int do_del(int argc, char **argv) {
  int ret = -1;
  std::string key;

  if (argc < 3) {
    do_del_help();
    goto end;
  }

  key = argv[2];
  ret = fcsync_del(key);
end:
  return ret;
}

uint64_t get_rtdsc()
{
    uint64_t tick1;
    unsigned c, d;

    asm volatile("rdtsc" : "=a" (c), "=d" (d));

    tick1 = (((uint64_t)c) | (((uint64_t)d) << 32));

    return tick1;
}

int do_get(int argc, char **argv) {
  int ret = -1;
  std::string host, key;
  uint64_t size;
  FcsyncClient *client;
  char *buf;
  uint64_t tstart, tend;

  if (argc < 5) {
    do_get_help();
    goto end;
  }
  host = argv[2];
  key = argv[3];
  size = atoi(argv[4]);

  client = new FcsyncClient(host, key);
  if (client == nullptr) {
    goto end;
  }

  client->load(0, size);

  buf = new char[size];
  sleep(1);  

  tstart = get_rtdsc();

  for (int i = 0; i < size / 1024; i++) {
    ret = client->read(buf + 1024 * i, size - 1024 * i, 1024, 0);
    if (ret == -1) {
      printf("ERROR!\n");
    }
  }

  tend = get_rtdsc();

  printf("%d\n", tend - tstart);


  printf("GET %s %s %d\n", host.c_str(), key.c_str(), size);

  

end_del_client:
  delete client;
end:
  return ret;
}



int main(int argc, char **argv) {
  int ret = -1;
  std::string cmd;

  if (argc < 2) {
    do_help();
    return -1;
  }
  cmd = argv[1];
  if (cmd == "add") {
    ret = do_add(argc, argv);     
  }
  else if (cmd == "get") {
    ret = do_get(argc, argv);
  }
  else if (cmd == "del") {
    ret = do_del(argc, argv);
  }
  return ret;
}