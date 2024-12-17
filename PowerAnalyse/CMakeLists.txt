# cmake_minimum_required (VERSION 3.16)

project("PowerAnalyse")

add_executable(PowerAnalyse 
    "main.cpp" 
    "function.cpp")

target_link_libraries(PowerAnalyse PRIVATE PowerUtils fmt::fmt)

add_library(LibPowerAnalyse "function.cpp")
target_include_directories(LibPowerAnalyse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(LibPowerAnalyse PUBLIC PowerUtils)

