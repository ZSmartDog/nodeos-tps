cmake_minimum_required(VERSION 3.13)

project(nodeos-tps)

find_package(Boost 1.6.7 REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})


set(CMAKE_CXX_STANDARD 17)

add_executable(main main.cpp)

add_subdirectory(serialization)
add_subdirectory(fc)
add_subdirectory(test)

target_include_directories(main PUBLIC fc/include)

target_link_libraries(main gmp fc serialization)