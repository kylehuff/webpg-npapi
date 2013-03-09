SYS := $(shell gcc -dumpmachine)
ifneq (, $(findstring linux, $(SYS)))
	OS = LINUX
else ifneq (, $(findstring darwin, $(SYS)))
	OS = DARWIN
else
	# Remaining should be all Windows (cygwin & mingw)
	OS = WINDOWS
	VS_VERSION := $(shell read -p "Enter your version of visual studio (i.e. 2008, 2010, 2012): " VS_VER_INPUT;\
		echo "$$VS_VER_INPUT";)
endif

ifeq ($(OS), WINDOWS)

endif

all: get-deps build
.PHONY: all

get-deps:
	git submodule update --init
	git submodule update --recursive
.PHONY: get-deps

build:
	@echo "Preparing build for $(OS)"
ifeq ($(OS), WINDOWS)
	cmd \/c .\\firebreath\\prep$(VS_VERSION).cmd\ webpgPlugin\ build
else ifeq ($(OS), DARWIN)
	./firebreath/prepmac.sh webpgPlugin build
else
	./firebreath/prepmake.sh webpgPlugin build
endif
ifeq ($(OS), WINDOWS)
	cmake --build build --config MinSizeRel
else
	cmake --build build --target webpgPlugin --config MinSizeRel
endif
.PHONY: build

clean:
ifeq ($(OS), WINDOWS)
	rmdir /s /q build
else
	rm -rf ./build
endif
.PHONY: clean
