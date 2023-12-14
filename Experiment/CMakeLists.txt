cmake_minimum_required(VERSION 3.26)
project(Experiment)

set(CMAKE_CXX_STANDARD 11)

add_executable(Experiment main.cpp
        src/MyScheme.cpp
        src/TestOpTime.cpp
        include/TestOpTime.h
        test/Test.cpp
        src/CCAP.cpp
        include/CCAP.h
        src/TestOpTime.cpp
        src/BASA.cpp
        include/BASA.h
        src/IRBA.cpp
        test/testMyScheme.cpp
)


target_include_directories(${PROJECT_NAME} PUBLIC core/cpp/)
target_include_directories(${PROJECT_NAME} PUBLIC include/)

target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/core/cpp/core.a)
