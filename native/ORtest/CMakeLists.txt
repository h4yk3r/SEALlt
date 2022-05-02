cmake_minimum_required(VERSION 3.5)

project(ORtest VERSION 0.1.1 LANGUAGES CXX)

find_package(SEAL 4.0 REQUIRED)
set(SEAL_DIR /usr/local/include/SEAL-4.0/seal/)

add_executable(main main.cpp)
target_link_libraries(main SEAL::seal)
