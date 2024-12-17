add_subdirectory(${THIRDPARTY_ROOT}/disasm)

if (NOT TARGET fmt::fmt)
    add_subdirectory(${THIRDPARTY_ROOT}/fmt)
endif()

if (NOT TARGET tomlplusplus::tomlplusplus)
    add_subdirectory(${THIRDPARTY_ROOT}/tomlplusplus)
endif()

if (NOT TARGET xxHash::xxhash)
    add_subdirectory(${THIRDPARTY_ROOT}/xxHash/cmake_unofficial)
endif()
