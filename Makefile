all:

build/Makefile:
	mkdir -p build
	(cd build; cmake ..)

%:: build/Makefile
	$(MAKE) -C build $@
