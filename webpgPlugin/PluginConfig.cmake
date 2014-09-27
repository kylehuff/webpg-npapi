#/**********************************************************\ 
#
# Auto-Generated Plugin Configuration file
# for webpg-plugin
#
#\**********************************************************/

set(PLUGIN_NAME "webpg")
set(PLUGIN_PREFIX "WEBPG")
set(COMPANY_NAME "CURETHEITCH")
set(CMAKE_BUILD_TYPE MinSizeRel)

# ActiveX constants:
set(FBTYPELIB_NAME webpgPluginLib)
set(FBTYPELIB_DESC "webpgPlugin 1.0 Type Library")
set(IFBControl_DESC "webpgPlugin Control Interface")
set(FBControl_DESC "webpgPlugin Control Class")
set(IFBComJavascriptObject_DESC "webpgPlugin IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "webpgPlugin ComJavascriptObject Class")
set(IFBComEventSource_DESC "webpgPlugin IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 9956ffdf-143c-5b7b-89c6-8a53bccb9969)
set(IFBControl_GUID eef357f7-e5d4-59ff-870d-205a046a3227)
set(FBControl_GUID b9c848b5-3ffb-5847-a6d6-4f9478a7a76f)
set(IFBComJavascriptObject_GUID db5b6071-e2b3-596a-abf0-5c62fa84908b)
set(FBComJavascriptObject_GUID 43b488b4-8132-58e9-87ee-79f96eaa01f2)
set(IFBComEventSource_GUID 7e55f947-88bb-5929-bd9d-7395de30fd0f)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CURETHEITCH.webpg-npapi")
set(MOZILLA_PLUGINID "curetheitch.com/webpg-npapi")

# enable pre-compiled headers
set(FB_USE_PCH TRUE)

# Sets the plugin in "extension only mode"
#   See note at http://webpg.org/docs/webpg-npapi/classwebpg_plugin_a_p_i_af99142391c5049c827cbe035812954f4.html
set(EXTENSIONIZE TRUE)

# Force building 32bit on 64bit
#   TRUE: Build 32bit on 64bit
#   FALSE: Build matching architecture
set(FORCE32 FALSE)

MESSAGE(STATUS "${CMAKE_SYSTEM_PROCESSOR} / ${CMAKE_SYSTEM_NAME}")

IF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686" OR CMAKE_SYSTEM_NAME MATCHES "Windows" OR FORCE32 OR CMAKE_SYSTEM_PROCESSOR MATCHES "armv7")
    # Currently maps *BSD to FreeBSD; may require more finite definition to make a
    #   distinction between FreeBSD and openBSD, etc.
    IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
        set(ARCH_DIR "FreeBSD_x86-gcc")
    ELSEIF (CMAKE_SYSTEM_PROCESSOR MATCHES "armv7")
        set(ARCH_DIR "Linux_armv7-gcc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Linux")
        set(ARCH_DIR "Linux_x86-gcc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(ARCH_DIR "WINNT_x86-msvc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        set(ARCH_DIR "Darwin_x86_64-gcc")
    ENDIF(CMAKE_SYSTEM_NAME MATCHES "BSD")
ELSE ()
    IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
        set(ARCH_DIR "FreeBSD_x86_64-gcc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Linux")
        set(ARCH_DIR "Linux_x86_64-gcc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(ARCH_DIR "WINNT_x86-msvc")
    ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        set(ARCH_DIR "Darwin_x86_64-gcc")
    ENDIF(CMAKE_SYSTEM_NAME MATCHES "BSD")
ENDIF()

message("Target architecture: ${ARCH_DIR}")

IF(EXTENSIONIZE)
    message("Setting _EXTENSIONIZE")
    set(PLUGIN_EXTENTIONIZE_NAME "-ext")
ELSE ()
    set(PLUGIN_EXTENTIONIZE_NAME "")
ENDIF(EXTENSIONIZE)

# strings
set(FBSTRING_CompanyName "CURE|THE|ITCH")
set(FBSTRING_FileDescription "A browser agnostic NPAPI interface to GnuPG")
set(FBSTRING_PLUGIN_VERSION "0.8.0")
set(FBSTRING_LegalCopyright "Copyright 2011-2013 CURE|THE|ITCH")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}${PLUGIN_EXTENTIONIZE_NAME}-v${FBSTRING_PLUGIN_VERSION}-${ARCH_DIR}")
set(FBSTRING_ProductName "WebPG")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "WebPG")
set(FBSTRING_PluginDescription "A browser agnostic NPAPI interface to GnuPG")
set(FBSTRING_MIMEType "application/x-webpg")

# Uncomment this next line if you're not planning on your plugin doing
# any drawing:
set (FB_GUI_DISABLED 1)

# Mac plugin settings. If your plugin does not draw, set these all to 0
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_CARBON 0)
set(FBMAC_USE_COCOA 0)
set(FBMAC_USE_COREGRAPHICS 0)
set(FBMAC_USE_COREANIMATION 0)
set(FBMAC_USE_INVALIDATINGCOREANIMATION 0)

# If you want to register per-machine on Windows, uncomment this line
#set (FB_ATLREG_MACHINEWIDE 1)

add_boost_library(regex)
add_firebreath_library(jsoncpp)
