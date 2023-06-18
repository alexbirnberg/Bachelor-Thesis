obj-m += filecache.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules VERBOSE=1
	clang -O2 -target bpf -g -I /usr/include/x86_64-linux-gnu -c bpf.c -o bpf.o

install:
	sudo insmod ./filecache.ko
	sudo bpftool prog load bpf.o /sys/fs/bpf/filecache type xdp
	sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/filecache dev ens33
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo bpftool net detach xdpgeneric dev ens33
	sudo rm /sys/fs/bpf/filecache
	sleep 1
	sudo rmmod filecache.ko