cmake_minimum_required(VERSION 3.16)
project(keysharp-input-install-consumer LANGUAGES C)

find_package(KeysharpInput 0.2 CONFIG REQUIRED)

add_executable(keysharp-input-install-consumer main.c)
target_link_libraries(keysharp-input-install-consumer PRIVATE
    KeysharpInput::client)
