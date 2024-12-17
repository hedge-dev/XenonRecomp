cmake_minimum_required (VERSION 3.20)

set(THIRDPARTY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)

set(CMAKE_CXX_STANDARD 17)
set(BUILD_SHARED_LIBS OFF)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include("cmake/bin2h.cmake")

add_subdirectory(${THIRDPARTY_ROOT})
set(POWERANALYSE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/PowerAnalyse)
set(POWERUTILS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/PowerUtils)
set(POWERRECOMP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/PowerRecomp)

project ("PowerRecomp-ALL")

add_subdirectory(${POWERANALYSE_ROOT})
add_subdirectory(${POWERRECOMP_ROOT})
add_subdirectory(${POWERUTILS_ROOT})

# Only build sample and tests if this is the top level project
if (${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_SOURCE_DIR})
    add_subdirectory(PowerSample)
    add_subdirectory(PowerTests)
endif()
