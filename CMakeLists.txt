cmake_minimum_required(VERSION 3.12)

project(asmrepl)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/external/asmtk")

add_executable(asmrepl "${CMAKE_CURRENT_LIST_DIR}/src/asmrepl.cpp")
target_link_libraries(asmrepl PRIVATE asmtk)
target_link_libraries(asmrepl PRIVATE asmjit)