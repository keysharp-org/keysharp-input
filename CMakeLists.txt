cmake_minimum_required(VERSION 3.16)

project(keysharp-input
    VERSION 0.1.0
    DESCRIPTION "Standalone privileged Linux input broker"
    HOMEPAGE_URL "https://github.com/keysharp-org/keysharp-input"
    LANGUAGES C)

include(CTest)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBUDEV REQUIRED IMPORTED_TARGET libudev)
pkg_check_modules(LIBEVDEV REQUIRED IMPORTED_TARGET libevdev)

set(KEYSHARP_INPUTD_PKCHECK_PATH "/usr/bin/pkcheck"
    CACHE FILEPATH "absolute path to the polkit authorization checker")

add_library(keysharp-input-auth STATIC src/auth.c src/shared_permissions.c)
target_include_directories(keysharp-input-auth PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(keysharp-input-auth PRIVATE
    _GNU_SOURCE
    _POSIX_C_SOURCE=200809L
    KSI_PKCHECK_PATH="${KEYSHARP_INPUTD_PKCHECK_PATH}")

add_executable(keysharp-inputd
    src/active_session.c
    src/connection_ref.c
    src/daemon.c
    src/ipc_unix.c
    src/main.c
    src/owned_text_file.c
    src/pipe_ring.c
    src/synthetic_hooks.c
    src/permissions_cli.c
    src/wake_pipe.c
    src/worker_pool.c)

target_include_directories(keysharp-inputd
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_definitions(keysharp-inputd PRIVATE
    _GNU_SOURCE
    _POSIX_C_SOURCE=200809L
    KSI_PRODUCT_VERSION="${PROJECT_VERSION}")
target_link_libraries(keysharp-inputd PRIVATE
    ${CMAKE_DL_LIBS}
    keysharp-input-auth
    Threads::Threads
    PkgConfig::LIBUDEV
    PkgConfig::LIBEVDEV)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(keysharp-inputd PRIVATE
        src/platform/linux_devices.c
        src/platform/linux_synth.c
        src/platform/platform_linux.c
        src/platform/vk_evdev.c)
    target_compile_definitions(keysharp-inputd PRIVATE KSI_PLATFORM_LINUX=1)
else()
    message(FATAL_ERROR "keysharp-inputd currently supports Linux only")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(keysharp-input-auth PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow)
    target_compile_options(keysharp-inputd PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow)
endif()

install(TARGETS keysharp-inputd
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

string(REGEX REPLACE "/+$" "" KEYSHARP_INPUTD_NORMALIZED_PREFIX
    "${CMAKE_INSTALL_PREFIX}")
if(KEYSHARP_INPUTD_NORMALIZED_PREFIX STREQUAL "/usr/local")
    set(KEYSHARP_INPUTD_DEFAULT_SYSTEMD_UNIT_DIR "/etc/systemd/system")
    set(KEYSHARP_INPUTD_DEFAULT_PACKAGED_UACCESS_RULE OFF)
else()
    set(KEYSHARP_INPUTD_DEFAULT_SYSTEMD_UNIT_DIR "lib/systemd/system")
    set(KEYSHARP_INPUTD_DEFAULT_PACKAGED_UACCESS_RULE ON)
endif()
set(KEYSHARP_INPUTD_SYSTEMD_UNIT_DIR
    "${KEYSHARP_INPUTD_DEFAULT_SYSTEMD_UNIT_DIR}"
    CACHE PATH "systemd system unit install directory")
option(KEYSHARP_INPUTD_INSTALL_PACKAGED_UACCESS_RULE
    "install the package-owned udev rule below the install prefix"
    ${KEYSHARP_INPUTD_DEFAULT_PACKAGED_UACCESS_RULE})
set(KEYSHARP_INPUTD_TMPFILES_DIR
    "lib/tmpfiles.d"
    CACHE STRING "systemd-tmpfiles configuration install directory")
if(IS_ABSOLUTE "${KEYSHARP_INPUTD_TMPFILES_DIR}")
    set(KEYSHARP_INPUTD_TMPFILES_CONFIG
        "${KEYSHARP_INPUTD_TMPFILES_DIR}/keysharp-input-permissions.conf")
else()
    set(KEYSHARP_INPUTD_TMPFILES_CONFIG
        "${CMAKE_INSTALL_PREFIX}/${KEYSHARP_INPUTD_TMPFILES_DIR}/keysharp-input-permissions.conf")
endif()

configure_file(
    systemd/keysharp-inputd.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/keysharp-inputd.service
    @ONLY)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/keysharp-inputd.service
    systemd/keysharp-inputd.socket
    DESTINATION ${KEYSHARP_INPUTD_SYSTEMD_UNIT_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
install(FILES systemd/keysharp-input-permissions.conf
    DESTINATION ${KEYSHARP_INPUTD_TMPFILES_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

if(KEYSHARP_INPUTD_NORMALIZED_PREFIX STREQUAL "/usr" OR
        KEYSHARP_INPUTD_NORMALIZED_PREFIX MATCHES "^/(nix|gnu)/store/")
    set(KEYSHARP_INPUTD_DEFAULT_POLKIT_ACTION_DIR
        "${CMAKE_INSTALL_DATADIR}/polkit-1/actions")
else()
    set(KEYSHARP_INPUTD_DEFAULT_POLKIT_ACTION_DIR "/usr/share/polkit-1/actions")
endif()
set(KEYSHARP_INPUTD_POLKIT_ACTION_DIR
    "${KEYSHARP_INPUTD_DEFAULT_POLKIT_ACTION_DIR}"
    CACHE STRING "polkit action install destination")
install(FILES polkit/org.keysharp.input.policy
    DESTINATION ${KEYSHARP_INPUTD_POLKIT_ACTION_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
if(KEYSHARP_INPUTD_INSTALL_PACKAGED_UACCESS_RULE)
    install(FILES udev/70-keysharp-inputd-uaccess.rules
        DESTINATION lib/udev/rules.d
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
install(FILES include/keysharp_inputd/protocol.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/keysharp-inputd
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
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
if(KEYSHARP_INPUTD_NORMALIZED_PREFIX STREQUAL "/usr/local")
    install(PROGRAMS packaging/uninstall.sh
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/keysharp-input)
endif()

# Direct root installs finish service setup immediately. Packaging installs
# set DESTDIR and should run the equivalent post-install step themselves.
option(KEYSHARP_INPUTD_SETUP_ON_INSTALL
    "configure udev/uinput/systemd after a direct root install" ON)
if(KEYSHARP_INPUTD_SETUP_ON_INSTALL)
    install(CODE "
        if(\"\$ENV{DESTDIR}\" STREQUAL \"\")
            set(_bin \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/keysharp-inputd\")
            execute_process(
                COMMAND \"\${_bin}\" --install-input-access
                RESULT_VARIABLE _inputd_setup_result)
            if(NOT _inputd_setup_result EQUAL 0)
                message(WARNING \"keysharp-inputd service setup was not completed; run as root: \${_bin} --install-input-access\")
            endif()
        endif()
    ")
endif()

option(KEYSHARP_INPUTD_BUILD_HOOKTEST "Build the installed-daemon diagnostic tool" ON)
option(KEYSHARP_INPUTD_BUILD_PHYSICAL_TEST_TOOL
    "Build the privileged manual physical-input source (never a CTest)" OFF)

if(KEYSHARP_INPUTD_BUILD_HOOKTEST)
    add_executable(keysharp-inputd-hooktest tools/hooktest.c)
    target_include_directories(keysharp-inputd-hooktest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(keysharp-inputd-hooktest PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-hooktest PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endif()

if(KEYSHARP_INPUTD_BUILD_PHYSICAL_TEST_TOOL)
    add_executable(keysharp-inputd-physical-source tools/physical-source.c)
    target_compile_definitions(keysharp-inputd-physical-source PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-physical-source PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endif()

if(BUILD_TESTING)
    add_executable(keysharp-inputd-unit-tests
        tests/daemon_unit_tests.c
        src/active_session.c
        src/connection_ref.c
        src/ipc_unix.c
        src/pipe_ring.c
        src/synthetic_hooks.c
        src/wake_pipe.c
        src/worker_pool.c
        src/platform/linux_devices.c
        src/platform/linux_synth.c
        src/platform/platform_linux.c
        src/platform/vk_evdev.c)

    target_include_directories(keysharp-inputd-unit-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-inputd-unit-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L KSI_PLATFORM_LINUX=1
        KSI_PRODUCT_VERSION="${PROJECT_VERSION}")
    target_link_libraries(keysharp-inputd-unit-tests PRIVATE
        ${CMAKE_DL_LIBS} keysharp-input-auth Threads::Threads
        PkgConfig::LIBUDEV PkgConfig::LIBEVDEV)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-unit-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-unit-tests COMMAND keysharp-inputd-unit-tests)

    add_executable(keysharp-inputd-scheduler-tests
        tests/scheduler_adversarial_tests.c
        src/connection_ref.c
        src/ipc_unix.c)
    target_include_directories(keysharp-inputd-scheduler-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-inputd-scheduler-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-inputd-scheduler-tests PRIVATE Threads::Threads)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-scheduler-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-scheduler-tests
        COMMAND keysharp-inputd-scheduler-tests)

    add_executable(keysharp-inputd-synthetic-hooks-tests
        tests/synthetic_hooks_tests.c
        src/synthetic_hooks.c)
    target_include_directories(keysharp-inputd-synthetic-hooks-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(keysharp-inputd-synthetic-hooks-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-synthetic-hooks-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-synthetic-hooks-tests
        COMMAND keysharp-inputd-synthetic-hooks-tests)

    add_executable(keysharp-inputd-pipe-ring-tests
        tests/pipe_ring_tests.c
        src/pipe_ring.c)
    target_include_directories(keysharp-inputd-pipe-ring-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-inputd-pipe-ring-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-inputd-pipe-ring-tests PRIVATE Threads::Threads)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-pipe-ring-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-pipe-ring-tests
        COMMAND keysharp-inputd-pipe-ring-tests)

    add_executable(keysharp-inputd-wake-pipe-tests
        tests/wake_pipe_tests.c
        src/wake_pipe.c)
    target_include_directories(keysharp-inputd-wake-pipe-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-inputd-wake-pipe-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-wake-pipe-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-wake-pipe-tests
        COMMAND keysharp-inputd-wake-pipe-tests)

    add_executable(keysharp-inputd-active-session-tests
        tests/active_session_tests.c
        src/active_session.c)
    target_include_directories(keysharp-inputd-active-session-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_definitions(keysharp-inputd-active-session-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    target_link_libraries(keysharp-inputd-active-session-tests PRIVATE
        ${CMAKE_DL_LIBS})

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-active-session-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-active-session-tests
        COMMAND keysharp-inputd-active-session-tests)

    add_executable(keysharp-inputd-linux-device-filter-tests
        tests/linux_device_filter_tests.c)
    target_include_directories(keysharp-inputd-linux-device-filter-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-linux-device-filter-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()

    add_test(NAME keysharp-inputd-linux-device-filter-tests
        COMMAND keysharp-inputd-linux-device-filter-tests)

    add_executable(keysharp-inputd-auth-tests tests/auth_tests.c)
    target_include_directories(keysharp-inputd-auth-tests PRIVATE src)
    target_link_libraries(keysharp-inputd-auth-tests PRIVATE keysharp-input-auth)
    target_compile_definitions(keysharp-inputd-auth-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-auth-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME keysharp-inputd-auth-tests COMMAND keysharp-inputd-auth-tests)

    add_executable(keysharp-inputd-owned-text-file-tests
        tests/owned_text_file_tests.c
        src/owned_text_file.c)
    target_include_directories(keysharp-inputd-owned-text-file-tests PRIVATE src)
    target_compile_definitions(keysharp-inputd-owned-text-file-tests PRIVATE
        _GNU_SOURCE _POSIX_C_SOURCE=200809L)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-inputd-owned-text-file-tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
    add_test(NAME keysharp-inputd-owned-text-file-tests
        COMMAND keysharp-inputd-owned-text-file-tests)

    add_test(NAME keysharp-inputd-systemd-unit-tests
        COMMAND ${CMAKE_COMMAND}
            -DKSI_SOCKET_UNIT=${CMAKE_CURRENT_SOURCE_DIR}/systemd/keysharp-inputd.socket
            -DKSI_SERVICE_UNIT=${CMAKE_CURRENT_SOURCE_DIR}/systemd/keysharp-inputd.service.in
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/systemd_unit_tests.cmake)
    add_test(NAME keysharp-inputd-packaging-lifecycle-test
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/packaging_lifecycle_test.cmake)
    add_test(NAME keysharp-inputd-portable-compatibility-tests
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/portable_compatibility_tests.sh
            ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME keysharp-inputd-debian-preinst-tests
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/debian_preinst_tests.sh
            ${CMAKE_CURRENT_SOURCE_DIR})
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
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libevdev2, libudev1, polkitd, udev, kmod, systemd")
set(CPACK_DEBIAN_PACKAGE_PROVIDES "keysharp-input-protocol-1.2")
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
