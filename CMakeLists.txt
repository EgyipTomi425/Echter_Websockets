cmake_minimum_required(VERSION 3.28)

project(Echter_Websockets LANGUAGES CXX)

include(CTest)

find_package(OpenSSL 3 REQUIRED COMPONENTS SSL)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(echter_websockets)
target_sources(echter_websockets
    PUBLIC
        FILE_SET CXX_MODULES FILES
            src/echter.cppm
            src/ws/client.cppm
            src/ws/compression.cppm
            src/ws/frame.cppm
            src/ws/handshake.cppm
    PRIVATE
        src/ws/client.cpp
        src/ws/compression.cpp
        src/ws/frame.cpp
        src/ws/handshake.cpp
)
target_link_libraries(echter_websockets PRIVATE OpenSSL::SSL PkgConfig::LIBURING ZLIB::ZLIB)

add_executable(localtest examples/main.cpp)
target_link_libraries(localtest PRIVATE echter_websockets)

if(BUILD_TESTING)
    add_executable(echter_ws_frame_tests tests/frame_tests.cpp)
    target_link_libraries(echter_ws_frame_tests PRIVATE echter_websockets)
    target_compile_options(echter_ws_frame_tests PRIVATE -UNDEBUG)
    add_test(NAME echter_ws_frame_tests COMMAND echter_ws_frame_tests)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    find_program(OPENSSL_COMMAND openssl)
    if(Python3_Interpreter_FOUND AND OPENSSL_COMMAND)
        add_executable(echter_ws_client_integration_tests tests/client_integration.cpp)
        target_link_libraries(echter_ws_client_integration_tests PRIVATE echter_websockets)
        add_test(NAME echter_ws_five_client_integration
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/loopback_wss.py
                $<TARGET_FILE:echter_ws_client_integration_tests> ${OPENSSL_COMMAND})
        set_tests_properties(echter_ws_five_client_integration PROPERTIES TIMEOUT 30)
        add_executable(echter_ws_lifecycle_tests tests/lifecycle_regression.cpp)
        target_link_libraries(echter_ws_lifecycle_tests PRIVATE echter_websockets)
        add_test(NAME echter_ws_lifecycle_regressions
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/lifecycle_peer.py
                $<TARGET_FILE:echter_ws_lifecycle_tests> ${OPENSSL_COMMAND})
        set_tests_properties(echter_ws_lifecycle_regressions PROPERTIES TIMEOUT 20)
    endif()
endif()
