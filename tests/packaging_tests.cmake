foreach(path
    CMakeLists.txt
    install.sh
    packaging/install-release.sh
    uninstall.sh
    packaging/debian/postinst
    packaging/debian/prerm
    systemd/keysharp-input.service.in
    systemd/keysharp-input.socket)
    file(READ "${SOURCE_DIR}/${path}" content)
    if(content MATCHES "keysharp-inputd\\.(service|socket)"
        OR content MATCHES "/run/keysharp-inputd"
        OR content MATCHES "KEYSHARP_INPUTD_")
        message(FATAL_ERROR "${path} contains a non-public service name")
    endif()
endforeach()

file(READ "${SOURCE_DIR}/CMakeLists.txt" cmake_source)
foreach(required
    "keysharp-input-client-abi-0"
    "SOVERSION 0"
    "include/keysharp_input/client.h"
    "include/keysharp_input/constants.h"
    "KeysharpInputTargets")
    string(FIND "${cmake_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "CMake packaging is missing ${required}")
    endif()
endforeach()

if(cmake_source MATCHES "keysharp-input-protocol-[0-9]")
    message(FATAL_ERROR "CMake packaging exposes the private service protocol")
endif()

file(READ "${SOURCE_DIR}/packaging/install-release.sh" installer)
foreach(required
    "expected_version=0.2.0"
    "expected_client_abi_major=0"
    "expected_client_abi_minor=2"
    "bin/keysharp-input"
    "lib/libkeysharp-input.so.0.2.0"
    "include/keysharp_input/client.h"
    "include/keysharp_input/constants.h"
    "client_abi_matches"
    "installation_complete_for_channel"
    "atomic_install_file \"$archive_dir/lib/libkeysharp-input.so.0.2.0\""
    "atomic_install_symlink libkeysharp-input.so.0.2.0"
    "atomic_install_file \"$archive_dir/bin/keysharp-input\""
    "current_library=$(portable_library_payload)"
    "--skip-if-compatible")
    string(FIND "${installer}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "portable installer is missing ${required}")
    endif()
endforeach()

foreach(forbidden
    "install -D -m 0755 \"$archive_dir/bin/keysharp-input\""
    "install -D -m 0755 \"$archive_dir/lib/libkeysharp-input.so.0.2.0\""
    "ln -sfn libkeysharp-input.so.0.2.0")
    string(FIND "${installer}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "portable installer overwrites a live artifact: ${forbidden}")
    endif()
endforeach()

if(installer MATCHES "grep -qx \"product_version=\\$expected_version\"")
    message(FATAL_ERROR "portable compatibility must use the public client ABI")
endif()

file(READ "${SOURCE_DIR}/packaging/debian/preinst" debian_preinst)
foreach(required
    "portable_library_conflicts"
    "/usr/local/lib/libkeysharp-input.so.0"
    "/usr/lib/libkeysharp-input.so.0")
    string(FIND "${debian_preinst}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Debian preinst is missing ${required}")
    endif()
endforeach()

file(READ "${SOURCE_DIR}/src/main.c" main_source)
foreach(required
    "client_abi_major=%u"
    "client_abi_minor=%u")
    string(FIND "${main_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "info metadata is missing ${required}")
    endif()
endforeach()

message(STATUS "keysharp-input packaging contract passed")
