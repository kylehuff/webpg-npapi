.PHONY: get-deps build

get-deps:
	git submodule init
	git submodule update

build:
	./firebreath/prepmake.sh webpgPlugin build
	cd ./build
	make webpgPlugin
