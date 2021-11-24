cmake_minimum_required(VERSION 3.16)

# Common stuff

# You might need to adjust this
set(MINGW_PATH /usr/x86_64-w64-mingw32)

set(SHLWAPI_PATH ${MINGW_PATH}/mingw/lib/libshlwapi.a)
set(WINPTHREAD_PATH ${MINGW_PATH}/usr/lib/libwinpthread.a)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

# Injected library

project(mhynot2 VERSION 1.0.0 DESCRIPTION "mhyprot2 user-mode emulator")

add_compile_definitions(mhynot2 UNICODE)

add_library(mhynot2 SHARED
    mhynot2-rewritten/Common.cpp
    mhynot2-rewritten/dllmain.cpp
    mhynot2-rewritten/EmulatorBackend.cpp
    mhynot2-rewritten/EmulatorBackend.h
    mhynot2-rewritten/mt64.cpp
    mhynot2-rewritten/PacketCrypt.cpp
    mhynot2-rewritten/PassthroughBackend.cpp
)

# Really hacky way, but I wasn't able to figure a better one
#set_target_properties(mhynot2 PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(mhynot2 PROPERTIES VERSION dll)
set_target_properties(mhynot2 PROPERTIES PREFIX "")
#set_target_properties(mhynot2 PROPERTIES SUFFIX .dll)
set_target_properties(mhynot2 PROPERTIES SUFFIX "")

set_target_properties(mhynot2 PROPERTIES SOVERSION 1)

target_include_directories(mhynot2 PRIVATE mhynot2-rewritten)
target_include_directories(mhynot2 PRIVATE minhook/include)

target_link_libraries(mhynot2 ${CMAKE_SOURCE_DIR}/minhook/libMinHook.a)
target_link_libraries(mhynot2 ${SHLWAPI_PATH})
target_link_libraries(mhynot2 ${WINPTHREAD_PATH})

target_link_options(mhynot2 PRIVATE -static-libgcc -static-libstdc++)

# Launcher executable

project(launcher VERSION 1.0.0 DESCRIPTION "DLL Injector for Genshin")

add_executable(launcher WIN32
    launcher/launcher.cpp
)

target_link_libraries(launcher ${SHLWAPI_PATH})
