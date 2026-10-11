cmake_minimum_required(VERSION 3.16)
project(DPIEngine VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

add_library(dpi_engine_core
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/dpi_engine.cpp
)
target_include_directories(dpi_engine_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dpi_engine_core PUBLIC Threads::Threads)

add_executable(dpi_engine src/main_dpi.cpp)
target_link_libraries(dpi_engine PRIVATE dpi_engine_core)

add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
target_include_directories(packet_analyzer PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(packet_analyzer PRIVATE Threads::Threads)

include(CTest)
if(BUILD_TESTING)
    add_executable(dpi_unit_tests tests/unit_tests.cpp)
    target_link_libraries(dpi_unit_tests PRIVATE dpi_engine_core)
    add_test(NAME dpi_unit_tests COMMAND dpi_unit_tests)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME dpi_scale_integration
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/scale_integration.py
                    $<TARGET_FILE:dpi_engine>
        )
        set_tests_properties(dpi_scale_integration PROPERTIES TIMEOUT 300)
    endif()
endif()
