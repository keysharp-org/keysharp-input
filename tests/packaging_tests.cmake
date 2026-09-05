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
string(REGEX MATCH
    "project\\(keysharp-input[ \t\r\n]+VERSION[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+)"
    project_declaration "${cmake_source}")
if(NOT project_declaration)
    message(FATAL_ERROR "CMake project version could not be read")
endif()
set(project_version "${CMAKE_MATCH_1}")

file(READ "${SOURCE_DIR}/include/keysharp_input/client.h" client_header)
foreach(component major minor)
    string(TOUPPER "${component}" macro_component)
    string(REGEX MATCH
        "#define KSI_CLIENT_ABI_${macro_component}[ \t]+([0-9]+)u?"
        abi_declaration "${client_header}")
    if(NOT abi_declaration)
        message(FATAL_ERROR "Client ABI ${component} could not be read")
    endif()
    set(client_abi_${component} "${CMAKE_MATCH_1}")
endforeach()

foreach(required
    "keysharp-input-client-abi-${client_abi_major}"
    "SOVERSION ${client_abi_major}"
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
    "expected_version=${project_version}"
    "expected_client_abi_major=${client_abi_major}"
    "expected_client_abi_minor=${client_abi_minor}"
    "bin/keysharp-input"
    "lib/libkeysharp-input.so.${project_version}"
    "include/keysharp_input/client.h"
    "include/keysharp_input/constants.h"
    "client_abi_matches"
    "installation_complete_for_channel"
    "atomic_install_file \"$archive_dir/lib/libkeysharp-input.so.${project_version}\""
    "atomic_install_symlink libkeysharp-input.so.${project_version}"
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
    "install -D -m 0755 \"$archive_dir/lib/libkeysharp-input.so.${project_version}\""
    "ln -sfn libkeysharp-input.so.${project_version}")
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
    "/usr/local/lib/libkeysharp-input.so.${client_abi_major}"
    "/usr/lib/libkeysharp-input.so.${client_abi_major}")
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
