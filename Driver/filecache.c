#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/uaccess.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/jhash.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/btf.h>
#include <linux/fs.h>

#include <net/xdp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Birnberg");
MODULE_DESCRIPTION("Kernel module for in-kernel file caching");
MODULE_VERSION("0.1");

#define DEBUG                   0
#define DEV_NAME                "filecache"
#define FILECACHE_MAX_EXTENTS   100000
#define FILECACHE_MAX_READ      0x10000000
#define FILECACHE_HASH_SIZE     16
#define FILECACHE_SECTOR_SZ     512
#define FILECACHE_MAX_SECTORS   127
#define FILECACHE_BUF_SZ        FILECACHE_MAX_SECTORS * FILECACHE_SECTOR_SZ
#define ex_size                 entry->extents[ex_cnt].size
#define ex_sector               entry->extents[ex_cnt].sector

DEFINE_HASHTABLE(filecache_files, FILECACHE_HASH_SIZE);
DEFINE_SPINLOCK(filecache_files_lock);

static inline unsigned int filecache_hashfn(int key)
{
  return jhash(&key, sizeof(key), 0) % FILECACHE_HASH_SIZE;
}

/**
 * Structure definitions
 */

struct filecache_add_req {
  char dev_path[PATH_MAX];
  __u32 key;
  __u32 extent_no;
  struct filecache_extent *extents;
} __attribute__ ((packed));

struct filecache_extent {
  __u32 sector;
  __u32 size;
} __attribute__ ((packed));

struct filecache_entry {
  struct kref refcount;
  struct block_device *bdev;
  __u32 key;
  __u32 extent_no;
  struct filecache_extent *extents;
  struct hlist_node node;
  struct rcu_head rcu;
  struct hlist_head contents[FILECACHE_HASH_SIZE];
};

struct filecache_content {
  __u32 id;
  struct page *page;
  unsigned int size;
  struct hlist_node node;
  struct rcu_head rcu;
};

/**
 * File cache file content functions
 */

int filecache_new_content(__u32 id, struct page *page, unsigned int size, struct filecache_content **result)
{
  int ret = -1;
  struct filecache_content *content;

  content = (struct filecache_content *)kzalloc(GFP_KERNEL, sizeof(*content));
  if (content == NULL) {
    goto end;
  }
  content->id = id;
  content->page = page;
  content->size = size;
  *result = content;
  ret = 0;
end:
  return ret;
}

void filecache_content_free(struct rcu_head *head)
{
  struct filecache_content *content = container_of(head, typeof(*content), rcu);

  __free_pages(content->page, get_order(content->size));
  kfree(content);
}

void filecache_insert_content(struct filecache_entry *entry, struct filecache_content *content)
{
  rcu_read_lock();
  hash_add_rcu(entry->contents, &content->node, filecache_hashfn(content->id));
  rcu_read_unlock();
}

void filecache_remove_content(struct filecache_content *content)
{
  rcu_read_lock();
  hash_del_rcu(&content->node);
  rcu_read_unlock();

  call_rcu(&content->rcu, filecache_content_free);
}

/**
 * File cache file entry functions 
 */

void filecache_free_entry_rcu(struct rcu_head *head)
{
  struct filecache_entry *entry = container_of(head, typeof(*entry), rcu);

  blkdev_put(entry->bdev, FMODE_READ);

  kfree(entry->extents);
  kfree(entry);
}

void filecache_free_entry(struct kref *ref)
{
  struct filecache_entry *entry = container_of(ref, struct filecache_entry, refcount);

  hash_del_rcu(&entry->node);
  call_rcu(&entry->rcu, filecache_free_entry_rcu);
}

void filecache_put_entry(struct filecache_entry *entry)
{
  kref_put(&entry->refcount, filecache_free_entry);
}

int filecache_new_entry(struct filecache_add_req *req, struct filecache_entry **result)
{
  int ret = -1;
  struct filecache_entry *entry, *tmp;
  bool add_file = true;

  entry = kzalloc(sizeof(struct filecache_entry), GFP_KERNEL);
  if (entry == NULL) {
    ret = -ENOMEM;
    goto end;
  }

  entry->extents = kvcalloc(req->extent_no, sizeof(*entry->extents), GFP_KERNEL);
  if (entry->extents == NULL) {
    ret = -ENOMEM;
    goto err_free_entry;
  }

  ret = copy_from_user(entry->extents, (void __user *)req->extents, req->extent_no * sizeof(*entry->extents));
  if (ret) {
    ret = -EFAULT;
    goto err_free_extents;
  }

  entry->bdev = blkdev_get_by_path(req->dev_path, FMODE_READ, NULL);
  if (IS_ERR(entry->bdev)) {
    ret = -ENOENT;
    goto err_free_extents;
  }

  entry->key = req->key;
  entry->extent_no = req->extent_no;
  kref_init(&entry->refcount);

  for (int i = 0; i < FILECACHE_HASH_SIZE; i++) {
    INIT_HLIST_HEAD(&entry->contents[i]);
  }

  spin_lock(&filecache_files_lock);

  hash_for_each_possible_rcu(filecache_files, tmp, node, filecache_hashfn(req->key)) {
    if (tmp->key == req->key) {
      add_file = false;
      break;
    }
  }

  if (add_file) {
    hash_add_rcu(filecache_files, &entry->node, filecache_hashfn(entry->key));
  }

  spin_unlock(&filecache_files_lock);

  *result = entry;
  ret = 0;
  goto end;

err_free_extents:
  kfree(entry->extents);
err_free_entry:
  kfree(entry);
end:
  return ret;
}

int filecache_find_entry(__u32 key, struct filecache_entry **result)
{
  int ret = -1;
  struct filecache_entry *tmp;
  
  rcu_read_lock();
  hash_for_each_possible_rcu(filecache_files, tmp, node, filecache_hashfn(key)) {
    if (tmp->key == key) {
      *result = tmp;
      kref_get(&tmp->refcount);
      break;
    }
  }
  if (*result == NULL) {
    ret = -ENOENT;
    goto end;
  }
  ret = 0;
end:
  rcu_read_unlock();
  return ret;
}

int filecache_del_entry(__u32 key)
{
  int ret = 0;
  struct filecache_entry *entry;

  ret = filecache_find_entry(key, &entry);
  if (ret < 0) {
    goto end;
  }
  filecache_put_entry(entry);
  filecache_put_entry(entry);
end:
  return ret;
}

void filecache_del_entries(void)
{
  int bkt;
  struct filecache_entry *entry;

  rcu_read_lock();
  if (!hash_empty(filecache_files)) {
    hash_for_each_rcu(filecache_files, bkt, entry, node) {
      filecache_put_entry(entry);
    }
  }
  rcu_read_unlock();
}

/**
 * Block device operations
 */

void filecache_read_sectors_complete(struct bio *bio)
{
  complete((struct completion *)bio->bi_private);
}

static long filecache_read_sectors(struct block_device *bdev, sector_t sector, int size, struct page *page)
{
  int ret = -EIO;
  struct completion event;
  struct bio *bio;

  bio = bio_alloc(bdev, 1, REQ_OP_READ, GFP_NOIO);
  if (unlikely(!bio)) {
    ret = -ENOMEM;
    goto out;
  }

  bio->bi_iter.bi_sector = sector; 
  init_completion(&event);
  bio->bi_private = &event;
  bio->bi_end_io = filecache_read_sectors_complete;

  while (size > 0) {
    int bio_size = min_t(int, size, PAGE_SIZE);
    struct page *bio_page = virt_to_page(page_address(page));

    ret = bio_add_page(bio, bio_page, bio_size, 0);
    if (unlikely(ret < 0)) {
      goto free_bio;
    }

    size -= bio_size;
    page = virt_to_page(page_address(page) + bio_size);
  }
  
  submit_bio(bio);

  wait_for_completion(&event);
  
  ret = 0;
free_bio:
  bio_put(bio);
out:
  return ret;
}

long filecache_read(struct filecache_entry *entry, char *buf, int buf__sz, __u32 key, __u64 pos, __u32 len)
{
  int ret = -1, ex_cnt = 0, read_sz, buf_len = 0, copy_len;
  bool found_extent = false;
  __u64 cursor = 0;
  unsigned int begin_sector, end_sector;
  struct page *page;

  // seek to pos
  len = len > buf__sz ? buf__sz : len;

  while (ex_cnt < entry->extent_no) {
    if (pos < cursor + ex_size) {
      found_extent = true;
      break;
    }
    cursor += ex_size;
    ex_cnt++;
  }
  if (found_extent == false) {
    ret = -ESPIPE;
    goto out;
  }
  pos -= cursor;

  // read extents
  while (ex_cnt < entry->extent_no && len > 0) {
    begin_sector = ex_sector + pos / FILECACHE_SECTOR_SZ;
    end_sector = begin_sector + len / FILECACHE_SECTOR_SZ;
    end_sector = end_sector > ex_sector + ex_size / FILECACHE_SECTOR_SZ ? ex_sector + ex_size / FILECACHE_SECTOR_SZ : end_sector + 1;
    read_sz = (end_sector - begin_sector) * FILECACHE_SECTOR_SZ;
    pos %= FILECACHE_SECTOR_SZ;

    page = alloc_pages(GFP_KERNEL, get_order(read_sz));
    if (page == NULL) {
      ret = -ENOMEM;
      goto out;
    }

    if (filecache_read_sectors(entry->bdev, begin_sector, read_sz, page) < 0) {
      ret = -EIO;
      goto out_free_pages;
    }

    if (end_sector == ex_sector + ex_size / FILECACHE_SECTOR_SZ) {
      ex_cnt++;
    }

    copy_len = read_sz > pos + len ? len : read_sz - pos;
    memcpy(buf + buf_len, page_address(page) + pos, copy_len);
    __free_pages(page, get_order(read_sz));
    pos = 0;
    buf_len += copy_len;
    len -= copy_len;
  }

  // return number of bytes read
  ret = buf_len;
  goto out;

out_free_pages:
  __free_pages(page, get_order(read_sz));
out:
  return ret;
}

/**
 * Kernel thread handling operation queue
 */

static struct task_struct *filecache_kthread;
DECLARE_WAIT_QUEUE_HEAD(filecache_wq);
static LIST_HEAD(filecache_queue);
static rwlock_t filecache_queue_rwlock;

#define FILECACHE_OP_EXIT 0x00000001
#define FILECACHE_OP_READ 0x00000002

struct filecache_op {
  int op;
  void *arg;
  struct list_head list;
};

// Generic queue operations

int filecache_queue_push(int op, void *arg)
{
  int ret = -1;
  struct filecache_op *fc_op;

  fc_op = (struct filecache_op *)kmalloc(GFP_KERNEL, sizeof(*fc_op));
  if (fc_op == NULL) {
    ret = -ENOMEM;
    goto end;
  }
  fc_op->op = op;
  fc_op->arg = arg;

  write_lock(&filecache_queue_rwlock);
  list_add_tail(&fc_op->list, &filecache_queue);
  write_unlock(&filecache_queue_rwlock);

  wake_up(&filecache_wq);
  ret = 0;
end:
  return ret;
}

int filecache_queue_pop(int *op, void **arg)
{
  int ret = -1;
  struct filecache_op *fc_op;

  write_lock(&filecache_queue_rwlock);
  if (!list_empty(&filecache_queue)) {
    fc_op = list_entry(filecache_queue.prev, struct filecache_op, list);
    list_del_init(&fc_op->list);
    *op = fc_op->op;
    *arg = fc_op->arg;
    kfree(fc_op);
    ret = 0;
  }
  write_unlock(&filecache_queue_rwlock);
  return ret;
}

bool filecache_queue_can_pop(void)
{
  bool ret; 

  read_lock(&filecache_queue_rwlock);
  ret = !list_empty(&filecache_queue);
  read_unlock(&filecache_queue_rwlock); 
  
  return ret;
}

// Filecache operations
struct filecache_op_read
{
  __u32 key;
  __u64 pos;
  __u32 len;
  __u32 id;
};

int bpf_filecache_load(__u32 key, __u64 pos, __u32 len, __u32 id)
{
  int ret = -1;
  struct filecache_op_read *arg;

  arg = (struct filecache_op_read *)kzalloc(GFP_KERNEL, sizeof(*arg));
  if (arg == NULL) {
    goto end;
  }
  if (len > FILECACHE_MAX_READ) {
    goto err_free_arg;
  }
  arg->key = key;
  arg->pos = pos;
  arg->len = len;
  arg->id = id;
  if (filecache_queue_push(FILECACHE_OP_READ, arg) < 0) {
    goto err_free_arg;
  }
  ret = 0;
  goto end;
err_free_arg:
  kfree(arg);
end:
  return ret;
}

void filecache_queue_op_read(void *arg)
{
  __u32 key, len, id;
  __u64 pos;
  struct filecache_entry *entry;
  struct filecache_content *content;
  struct page *page;

  key = ((struct filecache_op_read *)arg)->key;
  pos = ((struct filecache_op_read *)arg)->pos;
  len = ((struct filecache_op_read *)arg)->len;
  id  = ((struct filecache_op_read *)arg)->id;
  kfree(arg);

#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: inserting %x\n", key);
#endif
  if (filecache_find_entry(key, &entry) < 0) {
#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: failed to find entry\n");
#endif
    goto out;
  }
  page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(len));
  if (page == NULL) {
#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: failed to alloc pages\n");
#endif
    goto out_put_entry;
  }

  if (filecache_read(entry, page_address(page), len, key, pos, len) < 0) {
#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: failed to read data\n");
#endif
    goto out_free_pages;
  }

  if (filecache_new_content(id, page, len, &content) < 0) {
#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: failed to create new content\n");
#endif
    goto out_free_pages;
  }
#if DEBUG
    printk(KERN_INFO "filecache: filecache_queue_op_read: new entry inserted successfully\n");
#endif
  filecache_insert_content(entry, content);

  goto out_put_entry;
out_free_pages:
  __free_pages(page, get_order(len));
out_put_entry:
  filecache_put_entry(entry);
out:
  return;
}

int filecache_queue_thread(void *data)
{
  int op;
  void *arg;

  while (!kthread_should_stop()) {
    wait_event_interruptible(filecache_wq, filecache_queue_can_pop());

    if (filecache_queue_pop(&op, &arg) < 0) {
      continue;
    }

    switch (op) {
      case FILECACHE_OP_EXIT: {
        return 0;
      }
      case FILECACHE_OP_READ: {
        filecache_queue_op_read(arg);
        break;
      }
    }
  }
  return 0;
}

/**
 * BPF kfuncs
 */

#define FILECACHE_FLAGS_DEL     0x00000001

struct filecache_read_req
{
	uint16_t cmd;
	uint32_t key;
	uint64_t pos;
	uint32_t len;
	uint32_t id;
	uint32_t flags;
} __attribute__((__packed__));

int bpf_filecache_read(struct filecache_read_req *req, char *buf, int buf__sz)
{
  int ret = -1;
  uint32_t read_sz = req->len < buf__sz ? req->len : buf__sz;
  struct filecache_entry *entry;
  struct filecache_content *content = NULL;

  if (filecache_find_entry(req->key, &entry) < 0) {
#if DEBUG
    printk(KERN_INFO "filecache: bpf_filecache_read: failed to find entry %x\n", req->key);
#endif

    goto end;
  }
  rcu_read_lock();
  hash_for_each_possible_rcu(entry->contents, content, node, filecache_hashfn(req->id)) {
    if (content->id == req->id && req->pos < content->size) {
      read_sz = req->pos + read_sz < content->size ? read_sz : content->size - req->pos;
      memcpy(buf, page_address(content->page) + req->pos, read_sz);
      ret = read_sz;
#if DEBUG
    printk(KERN_INFO "filecache: bpf_filecache_read: found content\n");
#endif

      if (req->flags & FILECACHE_FLAGS_DEL) {
        filecache_remove_content(content);
      }
      
      break;
    }
  }
  rcu_read_unlock();
  filecache_put_entry(entry);

#if DEBUG
    printk(KERN_INFO "filecache: bpf_filecache_read: returning %x\n", ret);
#endif
end:
  return ret;
}

BTF_SET8_START(filecache_kfunc_set)
BTF_ID_FLAGS(func, bpf_filecache_load);
BTF_ID_FLAGS(func, bpf_filecache_read);
BTF_SET8_END(filecache_kfunc_set)

static const struct btf_kfunc_id_set bpf_filecache_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &filecache_kfunc_set
};

/**
 * IOCTLs
 */

#define IOCTL_ADD_FILE  _IOW('k', 1, int)
#define IOCTL_DEL_FILE  _IOW('k', 2, int)

static long filecache_ioctl_add(unsigned long arg) 
{
  long ret;
  struct filecache_add_req *req;
  struct filecache_entry *entry;

  req = kzalloc(sizeof(*req), GFP_KERNEL);
  if (req == NULL) {
    ret = -ENOMEM;
    goto out;
  }

  ret = copy_from_user(req, (void __user *)arg, sizeof(*req));
  if (ret) {
    ret = -EFAULT;
    goto err_free_req;
  }

  if (req->dev_path[PATH_MAX - 1]) {
    ret = -EFAULT;
    goto err_free_req;
  }

  if (req->extent_no > FILECACHE_MAX_EXTENTS) {
    ret = -ENOMEM;
    goto err_free_req;
  }

  ret = filecache_new_entry(req, &entry);
  if (ret < 0) {
    goto err_free_req;
  }

  ret = 0;
  goto err_free_req;

err_free_req:
  kfree(req);
out:
  return ret;
}

struct filecache_del_req {
  __u32 key;
};

static long filecache_ioctl_del(unsigned long arg)
{
  long ret = -ENOENT;
  struct filecache_del_req req;

  ret = copy_from_user(&req, (void __user *)arg, sizeof(req));
  if (ret) {
    ret = -EFAULT;
    goto out;
  }
  
  spin_lock(&filecache_files_lock);

  ret = filecache_del_entry(req.key);

  spin_unlock(&filecache_files_lock);

out:
  return ret;
}

static long filecache_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret = -1; 

  switch (cmd) {
    case IOCTL_ADD_FILE: {
      ret = filecache_ioctl_add(arg);
      break;
    }
    case IOCTL_DEL_FILE: {
      ret = filecache_ioctl_del(arg);
      break;
    }
  } 
  return ret;
}

static struct file_operations filecache_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = filecache_ioctl
};

/**
 * Driver initialization
 */
struct cdev filecache_cdev;
static dev_t filecache_dev;
struct class *filecache_class;

static int __init filecache_module_init(void)
{
  int ret = -1;
  struct device *dev;

  // Register BPF kfuncs
  ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_filecache_kfunc_set);
  if (ret) {
    printk(KERN_ERR "filecache: Failed to register eBPF kfuncs\n");
    goto out;
  }

  // Allocate major and minor numbers for the device
  ret = alloc_chrdev_region(&filecache_dev, 0, 1, DEV_NAME);
  if (ret < 0) {
    printk(KERN_ERR "filecache: Failed to allocate device number\n");
    goto out;
  }

  if (IS_ERR(filecache_class = class_create(THIS_MODULE, "filecache_class"))) {
    printk(KERN_ERR "filecache: Failed to create class\n");
    goto err_del_region;
  }

  // Initialize the character device
  cdev_init(&filecache_cdev, &filecache_fops);
  filecache_cdev.owner = THIS_MODULE;
  
  // Create device node
  if (IS_ERR(dev = device_create(filecache_class, NULL, filecache_dev, NULL, DEV_NAME))) {
    printk(KERN_ERR "filecache: Failed to create device\n");
    goto err_del_class;
  }

  // Add the character device to the kernel
  ret = cdev_add(&filecache_cdev, filecache_dev, 1);
  if (ret < 0) {
    printk(KERN_ERR "filecache: Failed to add character device\n");
    goto err_del_dev;
  }

  // Initialize operation queue
  rwlock_init(&filecache_queue_rwlock);
  filecache_kthread = kthread_run(filecache_queue_thread, NULL, "filecache-thread");
  if (IS_ERR(filecache_kthread)) {
    printk(KERN_ERR "filecache: Failed creating kthread\n");
    goto err_del_dev;
  }
  
  printk(KERN_INFO "filecache: driver loaded!\n");

  ret = 0;
  goto out;

err_del_dev:
  device_destroy(filecache_class, filecache_dev);
err_del_class:
  class_destroy(filecache_class);
err_del_region:
  unregister_chrdev_region(filecache_dev, 1);
out:
  return ret;
}

static void __exit filecache_module_exit(void)
{
  filecache_queue_push(FILECACHE_OP_EXIT, NULL);
 
  kthread_stop(filecache_kthread);

  filecache_del_entries();

  // Destroy the driver device
	device_destroy(filecache_class, filecache_dev);

  // Destroy the driver class
	class_destroy(filecache_class);

  // Remove the character device from the kernel
  cdev_del(&filecache_cdev);

  // Free the device number
  unregister_chrdev_region(filecache_dev, 1);

  printk(KERN_INFO "filecache: driver unloaded!\n");
}

module_init(filecache_module_init);
module_exit(filecache_module_exit);