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
)

IF(EXTENSIONIZE)
    add_definitions(-D_EXTENSIONIZE)
ENDIF(EXTENSIONIZE)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJECT_NAME} SOURCES)

IF(FORCE32)
    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
ENDIF(FORCE32)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME ${FBSTRING_PluginFileName}
)

add_library(gpgme STATIC IMPORTED)
set_property(TARGET gpgme PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpgme/${ARCH_DIR}/libgpgme.a)
add_library(gpg-error STATIC IMPORTED)
set_property(TARGET gpg-error PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libgpg-error/${ARCH_DIR}/libgpg-error.a)
add_library(assuan STATIC IMPORTED)
set_property(TARGET assuan PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libassuan/${ARCH_DIR}/libassuan.a)
add_library(curl STATIC IMPORTED)
set_property(TARGET curl PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libcurl/${ARCH_DIR}/libcurl.a)
add_library(mimetic STATIC IMPORTED)
set_property(TARGET mimetic PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libwebpg/libs/libmimetic/${ARCH_DIR}/libmimetic.a)

target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    gpgme
    assuan
    gpg-error
    curl
    mimetic
    )

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_link_libraries(${PROJECT_NAME}
        rt
    )
ENDIF()
