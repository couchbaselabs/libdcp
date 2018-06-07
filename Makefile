all:

build/Makefile:
	mkdir -p build
	(cd build; cmake -DCMAKE_BUILD_TYPE=DEBUG ..)

%:: build/Makefile
	$(MAKE) -C build $@
