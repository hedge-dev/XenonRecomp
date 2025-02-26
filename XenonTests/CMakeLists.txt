project("XenonTests")

file(GLOB TEST_FILES *.cpp)

if(TEST_FILES)
    add_executable(XenonTests 
        ${TEST_FILES}
    )
    target_link_libraries(XenonTests 
        PUBLIC 
            XenonUtils
            fmt::fmt
    )
    target_compile_options(XenonTests
        PRIVATE 
            "-march=sandybridge"
            "-Wno-unused-label"
            "-Wno-unused-variable"
    )
endif()
