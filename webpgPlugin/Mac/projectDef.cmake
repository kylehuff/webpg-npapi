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
    -D _FILE_OFFSET_BITS=64
    # See note at http://webpg.org/docs/webpg-npapi/classwebpg_plugin_a_p_i_af99142391c5049c827cbe035812954f4.html
    -D _EXTENSIONIZE
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
    gpg-error
    assuan
    )
