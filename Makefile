all:
	cd Tools/fcsync; make
	cd Driver; make

install:
	cd Driver
	sudo make . install