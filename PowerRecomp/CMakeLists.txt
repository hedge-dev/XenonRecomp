cmake_minimum_required (VERSION 3.8)

project("PowerRecomp")

BIN2H(SOURCE_FILE ${POWERUTILS_ROOT}/ppc_context.h HEADER_FILE "generated/ppc_context.gen.h" ARRAY_TYPE "char" VARIABLE_NAME "g_PPCContextText")

add_executable(PowerRecomp "main.cpp" "pch.h" "recompiler.cpp" "recompiler.h" "test_recompiler.cpp" "test_recompiler.h" "recompiler_config.h" "recompiler_config.cpp")
target_precompile_headers(PowerRecomp PUBLIC "pch.h")

find_package(fmt CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(tomlplusplus REQUIRED IMPORTED_TARGET tomlplusplus)
find_package(xxHash CONFIG REQUIRED)

target_link_libraries(PowerRecomp PRIVATE LibPowerAnalyse fmt::fmt PkgConfig::tomlplusplus xxHash::xxhash)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(PowerRecomp PRIVATE -Wno-switch -Wno-unused-variable -Wno-null-arithmetic)
endif()

target_compile_definitions(PowerRecomp PRIVATE _CRT_SECURE_NO_WARNINGS)
