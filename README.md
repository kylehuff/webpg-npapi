Description
===========
webpg-npapi is an NPAPI plugin project that provides GnuPG related Public/Private Key operations for use in major browsers.

This is a firebreath NPAPI plugin project, and this repository includes a submodule of FireBreath 1.5


Building Dependencies
=====================
* cmake
* development headers and libraries for libgpgme and gpg-error


Prep Build Environment
======================
From the root of this repository, type one of the following - depending on your OS:

Linux:

./firebreath/prepmake.sh . build

Windows:

For visual studio 2008: 
firebreath\prep2008.cmd . build

For visual studio 2009:
firebreath\prep2009.cmd . build

For visual studio 2010:
firebreath\prep2010.cmd . build

Mac OSX:

firebreath/prepmac.sh . build

(or to specify i386: firebreath/prepmac.sh . build -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_BUILD_TYPE=MinSizeRel)


Build the WebPG Plugin
======================
* cd ./build

Linux
-----
* make webpgPlugin

Mac OSX
-------
xcodebuild -target webpgPlugin

MS Windows
----------
cmake --build . --config MinSizeRel --target webpgPlugin


Move/Copy the plugin file to someplace accessible by the browser/extension
==========================================================================
Under linux, you can find the compiled .so file under:
build/bin/webpgPlugin/npwebpgPlugin.so

Under Windows you can find the compiled .dll file under:
build\bin\webpgPlugin\MinSizeRel\npwebpgPlugin.dll

Under Mac OSX you can find the compiled .plugin file under:
build/projects/webpgPlugin/MinSizeRel/webpgPlugin.plugin
