#/**********************************************************\ 
# Auto-generated Windows project definition file for the
# webpg-plugin project
#\**********************************************************/

# Windows template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in Win/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    Win/[^.]*.cpp
    Win/[^.]*.h
    Win/[^.]*.cmake
    )

# use this to add preprocessor definitions
add_definitions(
    /D "_ATL_STATIC_REGISTRY"
    /D "HAVE_W32_SYSTEM"
    /D "_FILE_OFFSET_BITS=64"
)

IF(EXTENSIONIZE)
    add_definitions(/D "_EXTENSIONIZE")
ENDIF(EXTENSIONIZE)

SOURCE_GROUP(Win FILES ${PLATFORM})

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_windows_plugin(${PROJECT_NAME} SOURCES)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME ${FBSTRING_PluginFileName}
)

# This is an example of how to add a build step to sign the plugin DLL before
# the WiX installer builds.  The first filename (certificate.pfx) should be
# the path to your pfx file.  If it requires a passphrase, the passphrase
# should be located inside the second file. If you don't need a passphrase
# then set the second filename to "".  If you don't want signtool to timestamp
# your DLL then make the last parameter "".
#
# Note that this will not attempt to sign if the certificate isn't there --
# that's so that you can have development machines without the cert and it'll
# still work. Your cert should only be on the build machine and shouldn't be in
# source control!
# -- uncomment lines below this to enable signing --
firebreath_sign_plugin(${PROJECT_NAME}
    "${CMAKE_CURRENT_SOURCE_DIR}/sign/certificate.pfx"
    "${CMAKE_CURRENT_SOURCE_DIR}/sign/passphrase.txt"
    "http://timestamp.verisign.com/scripts/timestamp.dll")

add_library(gpgme STATIC IMPORTED)
set_property(TARGET gpgme PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpgme/${ARCH_DIR}/libgpgme.lib)
add_library(gpg-error STATIC IMPORTED)
set_property(TARGET gpg-error PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpg-error/${ARCH_DIR}/libgpg-error.lib)
add_library(assuan STATIC IMPORTED)
set_property(TARGET assuan PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libassuan/${ARCH_DIR}/libassuan.lib)
add_library(curl STATIC IMPORTED)
set_property(TARGET curl PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libcurl/${ARCH_DIR}/libcurl.a)
add_library(mimetic STATIC IMPORTED)
set_property(TARGET mimetic PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libmimetic/${ARCH_DIR}/libmimetic.lib)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    gpgme
    assuan
    gpg-error
    mimetic
    curl
    )

#set(WIX_HEAT_FLAGS
#    -gg                 # Generate GUIDs
#    -srd                # Suppress Root Dir
#    -cg PluginDLLGroup  # Set the Component group name
#    -dr INSTALLDIR      # Set the directory ID to put the files in
#    )

#add_wix_installer( ${PLUGIN_NAME}
#    ${CMAKE_CURRENT_SOURCE_DIR}/Win/WiX/webpgPluginInstaller.wxs
#    PluginDLLGroup
#    ${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/
#    ${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/${FBSTRING_PluginFileName}.dll
#    ${PROJECT_NAME}
#    )

# This is an example of how to add a build step to sign the WiX installer
# -- uncomment lines below this to enable signing --
#firebreath_sign_file("${PLUGIN_NAME}_WiXInstall"
#    "${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/${PLUGIN_NAME}.msi"
#    "${CMAKE_CURRENT_SOURCE_DIR}/sign/certificate.pfx"
#    "${CMAKE_CURRENT_SOURCE_DIR}/sign/passphrase.txt"
#    "http://timestamp.verisign.com/scripts/timestamp.dll")
