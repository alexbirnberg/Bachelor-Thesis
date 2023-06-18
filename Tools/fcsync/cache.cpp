#include <iostream>
#include <algorithm>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <linux/fs.h>
#include <linux/fiemap.h>

#include "cache.hpp"

uint32_t fcsync_get_crc32(int fd) {
  uint32_t ret;
  int n;
  char buf[1024];

  lseek(fd, 0, SEEK_SET);
  ret = crc32(0L, Z_NULL, 0);

  while ((n = read(fd, buf, sizeof(buf))) > 0) {
      ret = crc32(ret, (const Bytef*)buf, n);
  }

  return ret;
}

struct fiemap *fcsync_read_fiemap(int fd) {
  struct fiemap *ret = nullptr, *fm, *fm_tmp;
  struct stat stat;
  int extents_size;
  uint32_t result_extents = 0;
  uint64_t fm_start = 0, fm_length;

  if (fstat(fd, &stat) < 0) {
    goto out;
  }
  
  fm_length = stat.st_size;

  fm = (fiemap *)malloc(sizeof(*fm));
  if (fm == nullptr) {
    goto out;
  }

  ret = (fiemap *)malloc(sizeof(*fm));
  if (ret == nullptr) {
    goto out_free_fm;
  }
  
  while (fm_start < fm_length) {
		memset(fm, 0, sizeof(*fm));

		fm->fm_start = fm_start;
		fm->fm_length = fm_length;
		fm->fm_flags = FIEMAP_FLAG_SYNC;

		if (ioctl(fd, FS_IOC_FIEMAP, fm) < 0) {
      goto out_free_ret;
		}

		if (fm->fm_mapped_extents == 0) {
			break;
    }

		extents_size = sizeof(fiemap_extent) * fm->fm_mapped_extents;
		fm_tmp = (fiemap *)realloc(fm, sizeof(*fm) + extents_size);

    if (fm_tmp == nullptr) {
      goto out_free_ret;
    }

		fm = fm_tmp;
		memset(fm->fm_extents, 0, extents_size);
		fm->fm_extent_count = fm->fm_mapped_extents;
		fm->fm_mapped_extents = 0;

		if (ioctl(fd, FS_IOC_FIEMAP, fm) < 0) {
      goto out_free_ret;
		}

		extents_size = sizeof(struct fiemap_extent) * (result_extents + fm->fm_mapped_extents);

		fm_tmp = (fiemap *)realloc(ret, sizeof(*ret) + extents_size);

		if (fm_tmp == nullptr) {
      goto out_free_ret;
		}
		ret = fm_tmp;

		memcpy(ret->fm_extents + result_extents, fm->fm_extents, sizeof(struct fiemap_extent) * fm->fm_mapped_extents);

		result_extents += fm->fm_mapped_extents;

		if (fm->fm_mapped_extents) {
			const uint32_t i = fm->fm_mapped_extents - 1;

			fm_start = fm->fm_extents[i].fe_logical + fm->fm_extents[i].fe_length;
      
			if (fm->fm_extents[i].fe_flags & FIEMAP_EXTENT_LAST)
				break;
		}
	}

	ret->fm_mapped_extents = result_extents;
	
  free(fm);
  goto out;

out_free_ret:
  free(ret);
out_free_fm:
  free(fm);
  ret = nullptr;
out:
  return ret;
}

int fcsync_add(std::string bdev, std::string path) {
  int ret = -1, fd, drv;
  struct fiemap *fm;
  struct filecache_add_req req = {};

  fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    goto out;
  }
  fm = fcsync_read_fiemap(fd);
  if (fm == nullptr) {
    std::cout << "[-] Failed getting extents" << std::endl;
    goto out_fd;
  }

  drv = open(DEV_NAME, O_RDWR);
  if (drv < 0) {
    std::cout << "[-] Failed opening driver" << std::endl;
    goto out_free_fm;
  }

  memcpy(req.dev_path, bdev.c_str(), std::min(bdev.length(), sizeof(req.dev_path) - 1));
  req.key = fcsync_get_crc32(fd);
  req.extent_no = fm->fm_mapped_extents;
  req.extents = (filecache_extent *)calloc(req.extent_no, sizeof(filecache_extent));

  if (req.extents == nullptr) {
    goto out_drv;
  }

  for (int i = 0; i < req.extent_no; i++) {
    req.extents[i].sector = fm->fm_extents[i].fe_physical / SECTOR_SIZE;
    req.extents[i].size = fm->fm_extents[i].fe_length;

    printf("sector=%x size=%x\n", req.extents[i].sector, req.extents[i].size);
  }

  if (ioctl(drv, IOCTL_ADD_FILE, &req) < 0) {
    std::cout << "[-] Failed adding file" << std::endl;
    goto out_free_extents;
  }

  std::cout << "[+] Added file" << std::endl << std::endl;

  std::cout << "Key: " << (void *)req.key << std::endl << std::endl;
  ret = 0;

out_free_extents:
  free(req.extents);
out_drv:
  close(drv);
out_free_fm:
  free(fm);  
out_fd:
  close(fd);
out:
  return ret;
}

int fcsync_del(std::string key) {
  int ret = -1, drv;
  std::stringstream ss;
  struct filecache_del_req req = {};

  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  if (key.substr(0, 2) == "0x") {
    key.erase(0, 2);
  }

  ss << std::hex << key;
  ss >> req.key;

  drv = open(DEV_NAME, O_RDWR);
  if (drv < 0) {
    goto out;
  }

  if (ioctl(drv, IOCTL_DEL_FILE, &req) < 0) {
    std::cout << "[-] Failed removing key" << std::endl;
    goto out_drv;
  }

  std::cout << "[+] Removed key " << (void *)req.key << std::endl;
  ret = 0;

out_drv:
  close(drv);
out:
  return ret;
}