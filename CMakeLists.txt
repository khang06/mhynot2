cmake_minimum_required(VERSION 3.16)

set (CMAKE_SYSTEM_NAME Windows)

# Injected library

project(mhynot2 VERSION 1.0.0 DESCRIPTION "mhyprot2 user-mode emulator")

add_library(mhynot2 SHARED
    mhynot2-rewritten/Common.cpp
    mhynot2-rewritten/dllmain.cpp
    mhynot2-rewritten/EmulatorBackend.cpp
    mhynot2-rewritten/EmulatorBackend.h
    mhynot2-rewritten/mt64.cpp
    mhynot2-rewritten/PacketCrypt.cpp
    mhynot2-rewritten/PassthroughBackend.cpp
)

target_compile_features(mhynot2 PRIVATE cxx_std_17)

add_subdirectory(minhook)
target_compile_definitions(mhynot2 PRIVATE UNICODE)
target_include_directories(mhynot2 PRIVATE mhynot2-rewritten)
target_link_libraries(mhynot2 minhook shlwapi)

if (MINGW)
    target_link_libraries(mhynot2 winpthread)
    target_link_options(mhynot2 PRIVATE -static-libgcc -static-libstdc++ -static)
endif()

# Launcher executable

project(launcher VERSION 1.0.0 DESCRIPTION "DLL Injector for Genshin")

add_executable(launcher WIN32
    launcher/launcher.cpp
)

target_link_libraries(launcher shlwapi)
