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
    # See note at http://webpg.org/docs/webpg-npapi/classwebpg_plugin_a_p_i_af99142391c5049c827cbe035812954f4.html
    -D_EXTENSIONIZE
)

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
