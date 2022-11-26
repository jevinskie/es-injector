# provides fat Mach-O targets 'frida-gum' and 'frida-core'

cmake_policy(SET CMP0135 NEW)
include(FetchContent)

set(FRIDA_VERSION 16.0.4)

#############
# frida-gum #
#############

FetchContent_Declare(
    frida-gum-x86_64
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gum-devkit-${FRIDA_VERSION}-macos-x86_64.tar.xz
)
FetchContent_MakeAvailable(frida-gum-x86_64)
FetchContent_GetProperties(frida-gum-x86_64 SOURCE_DIR FRIDA_GUM_X86_64_SRC_DIR)

FetchContent_Declare(
    frida-gum-arm64
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gum-devkit-${FRIDA_VERSION}-macos-arm64.tar.xz
)
FetchContent_MakeAvailable(frida-gum-arm64)
FetchContent_GetProperties(frida-gum-arm64 SOURCE_DIR FRIDA_GUM_ARM64_SRC_DIR)

FetchContent_Declare(
    frida-gum-arm64e
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gum-devkit-${FRIDA_VERSION}-macos-arm64e.tar.xz
)
FetchContent_MakeAvailable(frida-gum-arm64e)
FetchContent_GetProperties(frida-gum-arm64e SOURCE_DIR FRIDA_GUM_ARM64E_SRC_DIR)

set(FRIDA_GUM_THIN_LIBS
    ${FRIDA_GUM_X86_64_SRC_DIR}/libfrida-gum.a
    ${FRIDA_GUM_ARM64_SRC_DIR}/libfrida-gum.a
    ${FRIDA_GUM_ARM64E_SRC_DIR}/libfrida-gum.a
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libfrida-gum.a
    COMMAND lipo ${FRIDA_GUM_THIN_LIBS} -create -output ${CMAKE_CURRENT_BINARY_DIR}/libfrida-gum.a
    DEPENDS ${FRIDA_GUM_THIN_LIBS}
)

add_custom_target(
  frida-gum-fat
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libfrida-gum.a
)

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libfrida-gum.a)
target_include_directories(frida-gum INTERFACE ${FRIDA_GUM_ARM64_SRC_DIR})
add_dependencies(frida-gum frida-gum-fat)

##############
# frida-core #
##############

FetchContent_Declare(
    frida-core-x86_64
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-core-devkit-${FRIDA_VERSION}-macos-x86_64.tar.xz
)
FetchContent_MakeAvailable(frida-core-x86_64)
FetchContent_GetProperties(frida-core-x86_64 SOURCE_DIR FRIDA_CORE_X86_64_SRC_DIR)

FetchContent_Declare(
    frida-core-arm64
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-core-devkit-${FRIDA_VERSION}-macos-arm64.tar.xz
)
FetchContent_MakeAvailable(frida-core-arm64)
FetchContent_GetProperties(frida-core-arm64 SOURCE_DIR FRIDA_CORE_ARM64_SRC_DIR)

FetchContent_Declare(
    frida-core-arm64e
    FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER
    URL https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-core-devkit-${FRIDA_VERSION}-macos-arm64e.tar.xz
)
FetchContent_MakeAvailable(frida-core-arm64e)
FetchContent_GetProperties(frida-core-arm64e SOURCE_DIR FRIDA_CORE_ARM64E_SRC_DIR)

set(FRIDA_CORE_THIN_LIBS
    ${FRIDA_CORE_X86_64_SRC_DIR}/libfrida-core.a
    ${FRIDA_CORE_ARM64_SRC_DIR}/libfrida-core.a
    ${FRIDA_CORE_ARM64E_SRC_DIR}/libfrida-core.a
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libfrida-core.a
    COMMAND lipo ${FRIDA_CORE_THIN_LIBS} -create -output ${CMAKE_CURRENT_BINARY_DIR}/libfrida-core.a
    DEPENDS ${FRIDA_CORE_THIN_LIBS}
)

add_custom_target(
  frida-core-fat
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libfrida-core.a
)

add_library(frida-core STATIC IMPORTED GLOBAL)
set_target_properties(frida-core PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/libfrida-core.a)
target_include_directories(frida-core INTERFACE ${FRIDA_CORE_ARM64_SRC_DIR})
add_dependencies(frida-core frida-core-fat)
