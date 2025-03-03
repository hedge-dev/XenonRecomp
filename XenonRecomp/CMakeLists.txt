cmake_minimum_required (VERSION 3.8)

project("XenonRecomp")

add_executable(XenonRecomp 
    "main.cpp" 
    "recompiler.cpp"
    "test_recompiler.cpp" 
    "recompiler_config.cpp")

target_precompile_headers(XenonRecomp PUBLIC "pch.h")

target_link_libraries(XenonRecomp PRIVATE
    LibXenonAnalyse 
    XenonUtils 
    fmt::fmt
    tomlplusplus::tomlplusplus 
    xxHash::xxhash)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(XenonRecomp PRIVATE -Wno-switch -Wno-unused-variable -Wno-null-arithmetic)

    # alias attribute not supported on Apple.
    if (NOT APPLE)
        target_compile_definitions(XenonRecomp PRIVATE XENON_RECOMP_USE_ALIAS)
    endif()
endif()

target_compile_definitions(XenonRecomp PRIVATE _CRT_SECURE_NO_WARNINGS)
