#ifndef __CLIENT_HPP__
#define __CLIENT_HPP__

#include <stdint.h>
#include <arpa/inet.h>

#include <string>

#define FILECACHE_PORT 	        6666
#define FILECACHE_MAX_SECTORS   127

#define FILECACHE_CMD_READ 		  0x0000
#define FILECACHE_CMD_LOAD      0x0001
#define FILECACHE_FLAGS_DEL     0x00000001

struct filecache_req
{
	uint16_t cmd;
	uint8_t req[];
} __attribute__((__packed__));

struct filecache_read_req
{
	uint16_t cmd;
	uint32_t key;
	uint64_t pos;
	uint32_t len;
	uint32_t id;
	uint32_t flags;
} __attribute__((__packed__));

struct filecache_read_res
{
  int32_t len;
  uint8_t content[];
} __attribute__((__packed__));

struct filecache_load_req 
{
	uint16_t cmd;
	uint32_t key;
	uint64_t pos;
	uint32_t len;
	uint32_t id;
} __attribute__((__packed__));

struct filecache_load_res
{
  int32_t code;
} __attribute__((__packed__));

class FcsyncClient {
private:
  struct sockaddr_in sin;
  uint64_t pos = 0;
  uint32_t key;
  uint32_t id;

public:
  int read(char *buf, int buf_len, uint32_t len, uint32_t flags);
  int load(uint64_t pos, uint32_t len);
  void seek(uint64_t pos);
  FcsyncClient(std::string host, std::string key);
};

#endif // __CLIENT_HPP__
