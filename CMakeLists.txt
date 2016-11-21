cmake_policy(SET CMP0048 NEW)
cmake_minimum_required (VERSION 3.0)
project (docsis VERSION 0.1)

include(CheckCXXSourceCompiles)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
add_subdirectory (CMakeModules)

## find necessary libraries
find_package(Boost REQUIRED)
set(LDFLAGS ${LDFLAGS} ${Boost_LDFLAGS})
set(CXXFLAGS ${CXXFLAGS} ${Boost_CPPFLAGS})
include_directories (${Boost_INCLUDE_DIR})
message(STATUS "Boost-Include-Dir: ${Boost_INCLUDE_DIR}")
message(STATUS "Boost-Libs: ${Boost_LIBRARIES}")

include_directories(${CMAKE_SOURCE_DIR})
#set(LDFLAGS ${LDFLAGS} "{Boost_LDFLAGS})
#message(STATUS ${PNG_LIBRARIES})
#message(STATUS ${PNG_DEFINITIONS})

## removing trailing whitespaces
foreach (a ${LDFLAGS})
	set(b "${b} ${a}")
endforeach(a)
set(LDFLAGS ${b})
string(REGEX REPLACE "^[ \t]+|[ \t]+$" "" LDFLAGS "${LDFLAGS}")


if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	# using Clang
	message(STATUS "Compiling with Clang -- tested")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -ggdb -Wno-deprecated -O3 -march=native")
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -ggdb -Wno-deprecated -O0 -march=native")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	# using GCC
	message(STATUS "Compiling with GCC -- tested")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -O3 -march=native -mtune=native --fast-math -Wall -std=c++0x -Wno-deprecated -Xlinker -zmuldefs")
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -Wall -std=c++0x -Wno-deprecated -Xlinker -zmuldefs")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
	# using Intel C++
	message(STATUS "Compiling with Intel Compiler -- untested")

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	# using Visual Studio C++
	message(STATUS "Compiling with Visual Studio -- untested")

endif()

## define libraries and programs
set(LIBRARIES
	boost_regex
	boost_program_options
	boost_iostreams
	boost_filesystem
	boost_system
	boost_serialization
	boost_timer
)

## define subdirectories
set(LDFLAGS "${LDFLAGS}")

# # build modules for subdirectories
# set (MODULES)
# LIST (APPEND MODULES
# 	Utl
# 	Fwk
# 	Io
# 	Modules
# 	Math
# )
# foreach(mod ${MODULES})
# 	add_subdirectory(${mod})
# 	link_directories(${CMAKE_CURRENT_SOURCE_DIR}/${mod})
# 	set(LIBRARIES ${LIBRARIES} "mapisim${mod}")
# endforeach(mod)

add_executable(docsis main.cpp)
target_link_libraries(docsis ${LIBRARIES} "${LDFLAGS}")
