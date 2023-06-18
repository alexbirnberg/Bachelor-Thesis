all:
	cd Tools/fcsync
	make
	cd -
	cd Driver
	make

install:
	cd Driver
	sudo make install