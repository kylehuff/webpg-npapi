#/**********************************************************\ 
# 
# Auto-generated CMakeLists.txt for the webpg-plugin project
#
#\**********************************************************/

# Written to work with cmake 2.6
cmake_minimum_required (VERSION 2.6)
set (CMAKE_BACKWARDS_COMPATIBILITY 2.6)

Project(${PLUGIN_NAME})

file (GLOB GENERAL RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    )

file (GLOB LIBWEBPG RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    libwebpg/*.cpp
    libwebpg/*.cc
    libwebpg/*.h
    libwebpg/*.cmake
    )

include_directories(${PLUGIN_INCLUDE_DIRS})

# Generated files are stored in ${GENERATED} by the project configuration
SET_SOURCE_FILES_PROPERTIES(
    ${GENERATED}
    PROPERTIES
        GENERATED 1
    )

SOURCE_GROUP(Generated FILES
    ${GENERATED}
    )

SET( SOURCES
    ${GENERAL}
    ${LIBWEBPG}
    ${GENERATED}
    )

add_definitions(
    -D_FILE_OFFSET_BITS=64
    -DCURL_STATICLIB
    -I ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libcurl/${ARCH_DIR}/include
    -I ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpgme/${ARCH_DIR}/include
    -I ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpg-error/${ARCH_DIR}/include
    -I ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libmimetic/${ARCH_DIR}/include
)

# This will include Win/projectDef.cmake, X11/projectDef.cmake, Mac/projectDef 
# depending on the platform
include_platform()
