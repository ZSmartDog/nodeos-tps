cmake_minimum_required(VERSION 3.13)

project(test)

find_package(Boost 1.6.7 REQUIRED)

include_directories(${Boost_INCLUDE_DIRS} ../serialization)


set(CMAKE_CXX_STANDARD 17)

add_executable(test test_main.cpp
                    serialization/serialization_test.cpp
                    ../serialization/serialization.cpp
                    ../serialization/serialization.hpp
                    ../serialization/other_fc.hpp
                    ../serialization/other_fc.cpp
                    ../serialization/base58.hpp
                    ../serialization/base58.cpp)


#target_include_directories(test PUBLIC fc/include)
target_include_directories(test PUBLIC googletest)

target_link_libraries(test gmp serialization gtest pthread ssl crypto)