#/**********************************************************\ 
# Auto-generated Mac project definition file for the
# webpg-plugin project
#\**********************************************************/

# Mac template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in Mac/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    Mac/[^.]*.cpp
    Mac/[^.]*.h
    Mac/[^.]*.cmake
    )

# use this to add preprocessor definitions
add_definitions(
)

SOURCE_GROUP(Mac FILES ${PLATFORM})

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

set(PLIST "Mac/bundle_template/Info.plist")
set(STRINGS "Mac/bundle_template/InfoPlist.strings")
set(LOCALIZED "Mac/bundle_template/Localized.r")

add_mac_plugin(${PROJECT_NAME} ${PLIST} ${STRINGS} ${LOCALIZED} SOURCES)

add_library(gpgme STATIC IMPORTED)
set_property(TARGET gpgme PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libgpgme/Darwin_x86_64-gcc/libgpgme.a)
add_library(gpg-error STATIC IMPORTED)
set_property(TARGET gpg-error PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libgpg-error/Darwin_x86_64-gcc/libgpg-error.a)
add_library(assuan STATIC IMPORTED)
set_property(TARGET assuan PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libassuan/Darwin_x86_64-gcc/libassuan.a)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    gpgme
    gpg-error
    assuan
    )

set(PNAME "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/np${PLUGIN_NAME}-v${FBSTRING_PLUGIN_VERSION}.plugin")

# Rename plugin to np${PLUGIN_NAME}-v${FBSTRING_PLUGIN_VERSION}.plugin
ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${PNAME}
    COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${PROJECT_NAME}.plugin ${PNAME}
)

