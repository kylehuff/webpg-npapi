#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# webpg-plugin project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in X11/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    X11/[^.]*.cpp
    X11/[^.]*.h
    X11/[^.]*.cmake
    )

SOURCE_GROUP(X11 FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
    -D_FILE_OFFSET_BITS=64
    # Uncomment to compile for extension use only
    #-D_EXTENSIONIZE
)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJECT_NAME} SOURCES)

# Uncomment for building 32bit on 64bit (must have required 32bit system libs
#set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

IF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
    # Currently maps *BSD to FreeBSD; may require more finite definition to make a
    #   distinction between FreeBSD and openBSD, etc.
    IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
        set(ARCH_DIR "FreeBSD_x86_64-gcc")
    ELSE ()
        set(ARCH_DIR "Linux_x86_64-gcc")
    ENDIF(CMAKE_SYSTEM_NAME MATCHES "BSD")
ELSE ()
    IF(CMAKE_SYSTEM_NAME MATCHES "BSD")
        set(ARCH_DIR "FreeBSD_x86-gcc")
    ELSE ()
        set(ARCH_DIR "Linux_x86-gcc")
    ENDIF(CMAKE_SYSTEM_NAME MATCHES "BSD")
ENDIF(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")

add_library(gpgme STATIC IMPORTED)
set_property(TARGET gpgme PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libgpgme/${ARCH_DIR}/libgpgme.a)
add_library(gpg-error STATIC IMPORTED)
set_property(TARGET gpg-error PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libgpg-error/${ARCH_DIR}/libgpg-error.a)
add_library(assuan STATIC IMPORTED)
set_property(TARGET assuan PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libassuan/${ARCH_DIR}/libassuan.a)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    gpgme
    assuan
    gpg-error
    )

set(PNAME "${FB_BUILD_DIR}/bin/${PROJECT_NAME}/np${PLUGIN_NAME}-v${FBSTRING_PLUGIN_VERSION}.so")

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E rename ${FB_BUILD_DIR}/bin/${PROJECT_NAME}/np${PROJECT_NAME}.so ${PNAME}
)
