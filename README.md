Description
===========
webpg-npapi is an [NPAPI](https://developer.mozilla.org/en-US/docs/Plugins) plugin project that provides GnuPG related Public/Private Key operations for use in major browsers.

This is a [FireBreath](http://www.firebreath.org/display/documentation/FireBreath+Home) NPAPI plugin project, and this repository includes a submodule of FireBreath 1.5

Documentation
=============
Documentation and Class reference can be found here: http://webpg.org/docs/webpg-npapi/

Prerequisites
=============
In order for this plugin to work, you must have a working [GnuPG](http://www.gnupg.org/) installation.

Linux
-----

On Debian-based systems you can install GNUPG2 by running the command

```
sudo apt-get install gnupg2
```

Mac OSX
-------

The easiest way to install on OS X is to use the [GPGTools Installer](https://www.gpgtools.org/).


Building Dependencies
=====================
* [cmake](http://www.cmake.org/)


Prep Build Environment
======================
From the root of this repository, type one of the following - depending on your OS:

Linux
-----

```
./firebreath/prepmake.sh . build
```


Mac OSX
-------

### Universal Build ###

```
firebreath/prepmac.sh . build
```

### i386 Build ###

```
firebreath/prepmac.sh . build -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_BUILD_TYPE=MinSizeRel
```

### x86_64 Build ###

```
firebreath/prepmac.sh . build -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_BUILD_TYPE=MinSizeRel
```


MS Windows
----------

### For visual studio 2008 ###

```
firebreath\prep2008.cmd . build
```

### For visual studio 2009 ###

```
firebreath\prep2009.cmd . build
```

### For visual studio 2010 ###

```
firebreath\prep2010.cmd . build
```


Build the WebPG Plugin
======================

```
cd ./build
```

Linux
-----

```
make webpgPlugin
```

Mac OSX
-------

```
xcodebuild -target webpgPlugin
```

MS Windows
----------

```
cmake --build . --config MinSizeRel --target webpgPlugin
```


Move Copy the plugin file
=========================

Linux
-----

The compiled so file can be found at:


```
build/bin/webpgPlugin/npwebpgPlugin.so
```


Mac OSX
-------

The compiled .plugin file can be found at:

```
build/projects/webpgPlugin/MinSizeRel/webpgPlugin.plugin
```

MS Windows
----------

The compiled .dll file can be found at:

```
build\bin\webpgPlugin\MinSizeRel\npwebpgPlugin.dll
```


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/kylehuff/webpg-npapi/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

