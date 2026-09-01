cmake_minimum_required(VERSION 3.16)

project(keysharp-input
    VERSION 0.2.0
    DESCRIPTION "Standalone privileged Linux input broker"
    HOMEPAGE_URL "https://github.com/keysharp-org/keysharp-input"
    LANGUAGES C)

include(CTest)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBUDEV REQUIRED IMPORTED_TARGET libudev)
pkg_check_modules(LIBEVDEV REQUIRED IMPORTED_TARGET libevdev)

set(KEYSHARP_PERMISSIONS_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/keysharp-permissions"
    CACHE PATH "keysharp-permissions source directory (developer override)")
if(NOT EXISTS "${KEYSHARP_PERMISSIONS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "keysharp-permissions was not found; initialize the submodule with "
        "'git submodule update --init --recursive' or set "
        "KEYSHARP_PERMISSIONS_SOURCE_DIR for development")
endif()
add_subdirectory("${KEYSHARP_PERMISSIONS_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/keysharp-permissions" EXCLUDE_FROM_ALL)

set(KEYSHARP_INPUT_PKCHECK_PATH "/usr/bin/pkcheck"
    CACHE FILEPATH "absolute path to the polkit authorization checker")

add_library(keysharp-input-client SHARED src/client.c)
add_library(KeysharpInput::client ALIAS keysharp-input-client)
target_include_directories(keysharp-input-client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(keysharp-input-client PRIVATE
    _GNU_SOURCE _POSIX_C_SOURCE=200809L KEYSHARP_INPUT_CLIENT_BUILD=1
    KSI_PRODUCT_VERSION="${PROJECT_VERSION}")
target_link_libraries(keysharp-input-client PRIVATE
    KeysharpPermissions::permissions)
set_target_properties(keysharp-input-client PROPERTIES
    OUTPUT_NAME keysharp-input
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
    EXPORT_NAME client
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(keysharp-input-client PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(keysharp-input-service
    src/active_session.c
    src/connection_ref.c
    src/daemon.c
    src/ipc_unix.c
    src/main.c
    src/owned_text_file.c
    src/pipe_ring.c
    src/protocol_codec.c
    src/synthetic_hooks.c
    src/permissions_cli.c
    src/wake_pipe.c
    src/worker_pool.c)

target_include_directories(keysharp-input-service
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_definitions(keysharp-input-service PRIVATE
    _GNU_SOURCE
    _POSIX_C_SOURCE=200809L
    KSI_PRODUCT_VERSION="${PROJECT_VERSION}"
    KSI_PKCHECK_PATH="${KEYSHARP_INPUT_PKCHECK_PATH}")
target_link_libraries(keysharp-input-service PRIVATE
    ${CMAKE_DL_LIBS}
    keysharp-input-client
    KeysharpPermissions::permissions
    Threads::Threads
    PkgConfig::LIBUDEV
    PkgConfig::LIBEVDEV)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(keysharp-input-service PRIVATE
        src/platform/linux_devices.c
        src/platform/linux_synth.c
        src/platform/platform_linux.c
        src/platform/vk_evdev.c)
    target_compile_definitions(keysharp-input-service PRIVATE KSI_PLATFORM_LINUX=1)
else()
    message(FATAL_ERROR "keysharp-input currently supports Linux only")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(keysharp-input-service PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow)
endif()

set_target_properties(keysharp-input-service PROPERTIES OUTPUT_NAME keysharp-input)

install(TARGETS keysharp-input-service
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)
install(TARGETS keysharp-input-client
    EXPORT KeysharpInputTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

install(FILES
    include/keysharp_input/client.h
    include/keysharp_input/constants.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/keysharp_input)
configure_file(cmake/keysharp-input.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/keysharp-input.pc @ONLY)
configure_package_config_file(
    cmake/KeysharpInputConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/KeysharpInputConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KeysharpInput)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/KeysharpInputConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/keysharp-input.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/KeysharpInputConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/KeysharpInputConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KeysharpInput)
install(EXPORT KeysharpInputTargets
    FILE KeysharpInputTargets.cmake
    NAMESPACE KeysharpInput::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KeysharpInput)

string(REGEX REPLACE "/+$" "" KEYSHARP_INPUT_NORMALIZED_PREFIX
    "${CMAKE_INSTALL_PREFIX}")
if(KEYSHARP_INPUT_NORMALIZED_PREFIX STREQUAL "/usr/local")
    set(KEYSHARP_INPUT_DEFAULT_SYSTEMD_UNIT_DIR "/etc/systemd/system")
    set(KEYSHARP_INPUT_DEFAULT_PACKAGED_UACCESS_RULE OFF)
else()
    set(KEYSHARP_INPUT_DEFAULT_SYSTEMD_UNIT_DIR "lib/systemd/system")
    set(KEYSHARP_INPUT_DEFAULT_PACKAGED_UACCESS_RULE ON)
endif()
set(KEYSHARP_INPUT_SYSTEMD_UNIT_DIR
    "${KEYSHARP_INPUT_DEFAULT_SYSTEMD_UNIT_DIR}"
    CACHE PATH "systemd system unit install directory")
option(KEYSHARP_INPUT_INSTALL_PACKAGED_UACCESS_RULE
    "install the package-owned udev rule below the install prefix"
    ${KEYSHARP_INPUT_DEFAULT_PACKAGED_UACCESS_RULE})
set(KEYSHARP_INPUT_TMPFILES_DIR
    "lib/tmpfiles.d"
    CACHE STRING "systemd-tmpfiles configuration install directory")
if(IS_ABSOLUTE "${KEYSHARP_INPUT_TMPFILES_DIR}")
    set(KEYSHARP_INPUT_TMPFILES_CONFIG
        "${KEYSHARP_INPUT_TMPFILES_DIR}/keysharp-input-permissions.conf")
else()
    set(KEYSHARP_INPUT_TMPFILES_CONFIG
        "${CMAKE_INSTALL_PREFIX}/${KEYSHARP_INPUT_TMPFILES_DIR}/keysharp-input-permissions.conf")
endif()

configure_file(
    systemd/keysharp-input.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/keysharp-input.service
    @ONLY)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/keysharp-input.service
    systemd/keysharp-input.socket
    DESTINATION ${KEYSHARP_INPUT_SYSTEMD_UNIT_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(FILES systemd/keysharp-input-permissions.conf
    DESTINATION ${KEYSHARP_INPUT_TMPFILES_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

if(KEYSHARP_INPUT_NORMALIZED_PREFIX STREQUAL "/usr" OR
        KEYSHARP_INPUT_NORMALIZED_PREFIX MATCHES "^/(nix|gnu)/store/")
    set(KEYSHARP_INPUT_DEFAULT_POLKIT_ACTION_DIR
        "${CMAKE_INSTALL_DATADIR}/polkit-1/actions")
else()
    set(KEYSHARP_INPUT_DEFAULT_POLKIT_ACTION_DIR "/usr/share/polkit-1/actions")
endif()
set(KEYSHARP_INPUT_POLKIT_ACTION_DIR
    "${KEYSHARP_INPUT_DEFAULT_POLKIT_ACTION_DIR}"
    CACHE STRING "polkit action install destination")
install(FILES polkit/org.keysharp.input.policy
    DESTINATION ${KEYSHARP_INPUT_POLKIT_ACTION_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
if(KEYSHARP_INPUT_INSTALL_PACKAGED_UACCESS_RULE)
    install(FILES udev/70-keysharp-input-uaccess.rules
        DESTINATION lib/udev/rules.d
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
install(FILES README.md LICENSE PROVENANCE.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/keysharp-input
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(DIRECTORY docs/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/keysharp-input/docs
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)
if(KEYSHARP_INPUT_NORMALIZED_PREFIX STREQUAL "/usr/local")
    install(PROGRAMS uninstall.sh
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/keysharp-input)
endif()

# Direct root installs finish service setup immediately. Packaging installs
# set DESTDIR and should run the equivalent post-install step themselves.
option(KEYSHARP_INPUT_SETUP_ON_INSTALL
    "configure udev/uinput/systemd after a direct root install" ON)
if(KEYSHARP_INPUT_SETUP_ON_INSTALL)
    install(CODE "
        if(\"\$ENV{DESTDIR}\" STREQUAL \"\")
            set(_bin \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/keysharp-input\")
            execute_process(
                COMMAND \"\${_bin}\" daemon --install-input-access
                RESULT_VARIABLE _service_setup_result)
            if(NOT _service_setup_result EQUAL 0)
                message(WARNING \"keysharp-input service setup was not completed; run as root: \${_bin} daemon --install-input-access\")
            endif()
        endif()
    ")
endif()

option(KEYSHARP_INPUT_BUILD_PHYSICAL_TEST_TOOL
    "Build the privileged manual physical-input source (never a CTest)" OFF)

if(KEYSHARP_INPUT_BUILD_PHYSICAL_TEST_TOOL)
    add_executable(keysharp-input-physical-source tools/physical-source.c)
    target_compile_definitions(keysharp-input-physical-source PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-physical-source PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(keysharp-input-protocol-tests
        tests/protocol_tests.c src/protocol_codec.c)
    target_include_directories(keysharp-input-protocol-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME keysharp-input-protocol-tests
        COMMAND keysharp-input-protocol-tests)

    add_executable(keysharp-input-client-nested-tests
        tests/client_nested_tests.c)
    target_include_directories(keysharp-input-client-nested-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(keysharp-input-client-nested-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-input-client-nested-tests PRIVATE
        keysharp-input-client Threads::Threads)
    add_test(NAME keysharp-input-client-nested-tests
        COMMAND keysharp-input-client-nested-tests)

    add_executable(keysharp-input-daemon-admission-tests
        tests/daemon_admission_tests.c
        src/active_session.c
        src/connection_ref.c
        src/ipc_unix.c
        src/pipe_ring.c
        src/protocol_codec.c
        src/synthetic_hooks.c
        src/wake_pipe.c
        src/worker_pool.c
        src/platform/linux_devices.c
        src/platform/linux_synth.c
        src/platform/platform_linux.c
        src/platform/vk_evdev.c)
    target_include_directories(keysharp-input-daemon-admission-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-daemon-admission-tests PRIVATE
        _GNU_SOURCE
        _POSIX_C_SOURCE=200809L
        KSI_PLATFORM_LINUX=1
        KSI_PRODUCT_VERSION="${PROJECT_VERSION}"
        KSI_PKCHECK_PATH="${KEYSHARP_INPUT_PKCHECK_PATH}")
    target_link_libraries(keysharp-input-daemon-admission-tests PRIVATE
        ${CMAKE_DL_LIBS}
        KeysharpPermissions::permissions
        Threads::Threads
        PkgConfig::LIBUDEV
        PkgConfig::LIBEVDEV)
    add_test(NAME keysharp-input-daemon-admission-tests
        COMMAND keysharp-input-daemon-admission-tests)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-protocol-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        target_compile_options(keysharp-input-client-nested-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
        target_compile_options(keysharp-input-daemon-admission-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_executable(keysharp-input-scheduler-tests
        tests/scheduler_adversarial_tests.c
        src/connection_ref.c
        src/ipc_unix.c
        src/protocol_codec.c)
    target_include_directories(keysharp-input-scheduler-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-scheduler-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-input-scheduler-tests PRIVATE Threads::Threads)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-scheduler-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-scheduler-tests
        COMMAND keysharp-input-scheduler-tests)

    add_executable(keysharp-input-synthetic-hooks-tests
        tests/synthetic_hooks_tests.c
        src/synthetic_hooks.c)
    target_include_directories(keysharp-input-synthetic-hooks-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-synthetic-hooks-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-synthetic-hooks-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-synthetic-hooks-tests
        COMMAND keysharp-input-synthetic-hooks-tests)

    add_executable(keysharp-input-pipe-ring-tests
        tests/pipe_ring_tests.c
        src/pipe_ring.c)
    target_include_directories(keysharp-input-pipe-ring-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-pipe-ring-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-input-pipe-ring-tests PRIVATE Threads::Threads)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-pipe-ring-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-pipe-ring-tests
        COMMAND keysharp-input-pipe-ring-tests)

    add_executable(keysharp-input-wake-pipe-tests
        tests/wake_pipe_tests.c
        src/wake_pipe.c)
    target_include_directories(keysharp-input-wake-pipe-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-wake-pipe-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-wake-pipe-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-wake-pipe-tests
        COMMAND keysharp-input-wake-pipe-tests)

    add_executable(keysharp-input-active-session-tests
        tests/active_session_tests.c
        src/active_session.c)
    target_include_directories(keysharp-input-active-session-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-input-active-session-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-input-active-session-tests PRIVATE
        ${CMAKE_DL_LIBS})

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-active-session-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-active-session-tests
        COMMAND keysharp-input-active-session-tests)

    add_executable(keysharp-input-linux-device-filter-tests
        tests/linux_device_filter_tests.c)
    target_include_directories(keysharp-input-linux-device-filter-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-linux-device-filter-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-input-linux-device-filter-tests
        COMMAND keysharp-input-linux-device-filter-tests)

    add_executable(keysharp-input-owned-text-file-tests
        tests/owned_text_file_tests.c
        src/owned_text_file.c)
    target_include_directories(keysharp-input-owned-text-file-tests PRIVATE src)
    target_compile_definitions(keysharp-input-owned-text-file-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-owned-text-file-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME keysharp-input-owned-text-file-tests
        COMMAND keysharp-input-owned-text-file-tests)

    add_test(NAME keysharp-input-systemd-unit-tests
        COMMAND ${CMAKE_COMMAND}
            -DKSI_SOCKET_UNIT=${CMAKE_CURRENT_SOURCE_DIR}/systemd/keysharp-input.socket
            -DKSI_SERVICE_UNIT=${CMAKE_CURRENT_SOURCE_DIR}/systemd/keysharp-input.service.in
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/systemd_unit_tests.cmake)
    add_test(NAME keysharp-input-packaging-tests
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/packaging_tests.cmake)
    add_test(NAME keysharp-input-packaging-semantics-tests
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/packaging_semantics_tests.sh
            ${CMAKE_CURRENT_SOURCE_DIR})
endif()

option(KEYSHARP_INPUT_BUILD_BENCHMARKS
    "build local callback round-trip benchmarks" OFF)
if(KEYSHARP_INPUT_BUILD_BENCHMARKS)
    add_executable(keysharp-input-hook-benchmark
        benchmarks/hook_roundtrip.c)
    target_include_directories(keysharp-input-hook-benchmark PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(keysharp-input-hook-benchmark PRIVATE
        keysharp-input-client Threads::Threads)
    target_compile_definitions(keysharp-input-hook-benchmark PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-input-hook-benchmark PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endif()

set(CPACK_PACKAGE_NAME "keysharp-input")
set(CPACK_PACKAGE_VENDOR "Descolada")
set(CPACK_PACKAGE_CONTACT
    "Descolada <16986957+Descolada@users.noreply.github.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE
    "https://github.com/keysharp-org/keysharp-input")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Privileged Linux input broker")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
    "keysharp-input-${PROJECT_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "polkitd, udev, kmod, systemd")
set(CPACK_DEBIAN_PACKAGE_PROVIDES "keysharp-input-client-abi-0")
set(KEYSHARP_INPUT_DEBIAN_CONTROLS)
foreach(script preinst postinst prerm postrm)
    file(COPY packaging/debian/${script}
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
        FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    list(APPEND KEYSHARP_INPUT_DEBIAN_CONTROLS
        ${CMAKE_CURRENT_BINARY_DIR}/${script})
endforeach()
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${KEYSHARP_INPUT_DEBIAN_CONTROLS}")
include(CPack)
