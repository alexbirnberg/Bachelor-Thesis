#include "client.hpp"

#include <iostream>
#include <sstream>
#include <algorithm>

#include <time.h>
#include <string.h>
#include <unistd.h>

FcsyncClient::FcsyncClient(std::string host, std::string key) {
  std::stringstream ss(key);

  memset(&this->sin, 0, sizeof(this->sin));
  this->sin.sin_family = AF_INET;
  this->sin.sin_port = htons(FILECACHE_PORT);
  inet_aton(host.c_str(), &this->sin.sin_addr);
  srand(time(0));
  this->id = rand() * 0xdeadbeef;

  if (key.substr(0, 2) == "0x") {
    key = key.substr(2);
  }
  ss >> std::hex >> this->key;
}

int FcsyncClient::read(char *buf, int buf_len, uint32_t len, uint32_t flags) {
  int s, ret = -1, read_sz = len < buf_len ? len : buf_len;
  char tmp[0x1000] = {};
  struct filecache_read_req req;
  struct filecache_read_res *res = (struct filecache_read_res *)tmp;

  read_sz = read_sz < sizeof(tmp) - sizeof(*res) ? read_sz : sizeof(tmp) - sizeof(*res);

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    goto end;
  }
  req.cmd   = FILECACHE_CMD_READ;
  req.key   = this->key;
  req.pos   = this->pos;
  req.len   = len;
  req.id    = this->id;
  req.flags = flags;

  ret = sendto(s, &req, sizeof(req), 0, (struct sockaddr *)&this->sin, sizeof(this->sin));
  if (ret < 0) {
    goto end_close;
  }
  ret = recvfrom(s, res, sizeof(tmp), 0, NULL, NULL);
  if (ret < sizeof(*res)) {
    goto end_close;
  }
  if (res->len + sizeof(*res) > ret) {
    goto end_close;
  }
  if (res->len == -1) {
    goto end_close;
  }
  read_sz = res->len < read_sz ? res->len : read_sz;
  memcpy(buf, res->content, read_sz);
  ret = read_sz;
  this->pos += ret;
end_close:
  close(s);
end:
  return ret;
}

int FcsyncClient::load(uint64_t pos, uint32_t len) {
  int s, ret = -1;
  struct filecache_load_req req;
  struct filecache_load_res res;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    goto end;
  }
  req.cmd = FILECACHE_CMD_LOAD;
  req.key = this->key;
  req.pos = pos;
  req.len = len;
  req.id  = this->id % 0x7fffffff;

  ret = sendto(s, &req, sizeof(req), 0, (struct sockaddr *)&this->sin, sizeof(this->sin));
  if (ret < 0) {
    goto end_close;
  }
  ret = recvfrom(s, &res, sizeof(res), 0, NULL, NULL);
  if (ret < 0) {
    goto end_close;
  }
  if (res.code == 0) {
    ret = req.id;
  }
end_close:
  close(s);
end:
  return ret;
}

void FcsyncClient::seek(uint64_t pos) {
  this->pos = pos;
}