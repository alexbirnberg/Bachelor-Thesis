#ifndef __CACHE_HPP__
#define __CACHE_HPP__
#include <string>

#include <stdint.h>

#include <linux/limits.h>

#define DEV_NAME      "/dev/filecache"
#define SECTOR_SIZE   512

#define IOCTL_ADD_FILE  _IOW('k', 1, int)
#define IOCTL_DEL_FILE  _IOW('k', 2, int)

struct filecache_extent {
  uint32_t sector;
  uint32_t size;
} __attribute__ ((packed));

struct filecache_add_req {
  char dev_path[PATH_MAX];
  uint32_t key;
  uint32_t extent_no;
  struct filecache_extent *extents;
} __attribute__ ((packed));

struct filecache_del_req {
  uint32_t key;
};

int fcsync_add(std::string bdev, std::string path);

int fcsync_del(std::string key);

#endif // __CACHE_HPP__
