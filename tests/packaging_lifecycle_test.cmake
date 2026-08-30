file(READ "${SOURCE_DIR}/packaging/install.sh" portable_installer)
file(READ "${SOURCE_DIR}/packaging/uninstall.sh" portable_uninstaller)
file(READ "${SOURCE_DIR}/packaging/debian/postrm" debian_postrm)
file(READ "${SOURCE_DIR}/packaging/debian/postinst" debian_postinst)
file(READ "${SOURCE_DIR}/packaging/debian/preinst" debian_preinst)
file(READ "${SOURCE_DIR}/systemd/keysharp-inputd.service.in" service_unit)
file(READ "${SOURCE_DIR}/systemd/keysharp-input-permissions.conf" tmpfiles_config)
file(READ "${SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${SOURCE_DIR}/nix/package.nix" nix_package)
file(READ "${SOURCE_DIR}/nix/module.nix" nix_module)
file(READ "${SOURCE_DIR}/.github/workflows/release.yml" release_workflow)
file(READ "${SOURCE_DIR}/.github/workflows/ci.yml" ci_workflow)
file(READ "${SOURCE_DIR}/src/main.c" main_source)
file(READ "${SOURCE_DIR}/src/daemon.c" daemon_source)
file(READ "${SOURCE_DIR}/src/daemon/grab_leases.inc" grab_source)
file(READ "${SOURCE_DIR}/src/auth.c" auth_source)
file(READ "${SOURCE_DIR}/src/permissions_cli.c" permissions_cli_source)
file(READ "${SOURCE_DIR}/src/owned_text_file.c" owned_text_source)
file(READ "${SOURCE_DIR}/include/keysharp_inputd/protocol.h" protocol_source)
file(READ "${SOURCE_DIR}/polkit/org.keysharp.input.policy" polkit_policy)
file(READ "${SOURCE_DIR}/tests/portable_compatibility_tests.sh"
    compatibility_tests)

foreach(required
        "--skip-if-compatible"
        "/run/current-system/sw/bin/keysharp-inputd"
        "layered_install_present"
        "installation_complete"
        "service_configuration_matches"
        "socket_configuration_matches"
        "policy_configuration_matches"
        "tmpfiles_configuration_matches"
        "uaccess_configuration_matches"
        "installed_resource_is_valid"
        "archive_service_configuration_matches"
        "archive_socket_configuration_matches"
        "archive_complete"
        "expected_protocol_name=keysharp-inputd/windows-input-v1"
        "archive_version"
        "archive_protocol_minor"
        "--system-service"
        "/run/keysharp-inputd/keysharp-inputd.sock (Stream)"
        "70-keysharp-inputd-uaccess.rules"
        "systemd-tmpfiles --create"
        "include/keysharp-inputd/protocol.h"
        "app-identity.md permission-store.md"
        "physical-live-tests.md protocol.md"
        "PROVENANCE.md"
        "/usr/local/share/doc/keysharp-input/uninstall.sh")
    string(FIND "${portable_installer}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "portable installer is missing ${required}")
    endif()
endforeach()

foreach(required
        "argv[]=$binary --system-service extra"
        "/tmp/input.sock (Stream)"
        "(Datagram)"
        "insecure.policy"
        "missing-message.policy"
        "extra-action.policy"
        "insecure.tmpfiles"
        "insecure.rules"
        "insecure.service"
        "weak-service.service"
        "extra-device.service"
        "insecure.socket"
        "unprotected-link")
    string(FIND "${compatibility_tests}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "negative compatibility coverage is missing ${required}")
    endif()
endforeach()

foreach(required
        "inotify_init1(IN_NONBLOCK | IN_CLOEXEC)"
        "process_permission_notifications"
        "permission_monitor_fail_open")
    string(FIND "${grab_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "event-driven permission monitoring is missing ${required}")
    endif()
endforeach()
string(FIND "${daemon_source}" "KSI_PERMISSION_REFRESH_MS" found)
if(NOT found EQUAL -1)
    message(FATAL_ERROR "daemon must not poll the permission store on a timer")
endif()
foreach(required
        ".prompt-%lu-%s.lock"
        "O_NOFOLLOW"
        "LOCK_EX | LOCK_NB"
        "fchmod(descriptor, 0600)")
    string(FIND "${auth_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "shared prompt serialization is missing ${required}")
    endif()
endforeach()

foreach(required
        "include/keysharp_inputd/protocol.h"
        "$root/include/keysharp-inputd/protocol.h"
        "$root/udev/70-keysharp-inputd-uaccess.rules"
        "install -m 0644 docs/*.md"
        "LICENSE README.md PROVENANCE.md")
    string(FIND "${release_workflow}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "portable release payload is missing ${required}")
    endif()
endforeach()
foreach(required
        "dpkg-deb -f"
        "keysharp-input-protocol-1.2")
    string(FIND "${release_workflow}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "release workflow does not validate Debian ABI metadata: ${required}")
    endif()
endforeach()
foreach(required
        "id: nix-lock"
        "if: steps.nix-lock.outputs.enabled == 'true'"
        "nix flake check --no-write-lock-file")
    string(FIND "${ci_workflow}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "conditional Nix validation is missing ${required}")
    endif()
endforeach()
string(FIND "${release_workflow}" "Release blocked: generate" found)
if(NOT found EQUAL -1)
    message(FATAL_ERROR "an absent Nix lock must not block tar or Debian releases")
endif()

if(nix_module MATCHES
        "systemd\\.sockets\\.keysharp-inputd = \\{[^}]*wantedBy")
    message(FATAL_ERROR
        "Nix socket must not be an independent boot entry point")
endif()
foreach(required
        "systemd.services.keysharp-inputd = {"
        "wantedBy = [ \"multi-user.target\" ];"
        "requires = [ \"keysharp-inputd.socket\" ];")
    string(FIND "${nix_module}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "Nix service must be the boot entry and require its socket: ${required}")
    endif()
endforeach()

foreach(required
        "/var/lib/keysharp-permissions 0700 root root"
        "/var/lib/keysharp-permissions/v1 0700 root root"
        "/run/keysharp-permissions 0755 root root")
    string(FIND "${tmpfiles_config}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "tmpfiles contract is missing ${required}")
    endif()
    string(FIND "${nix_module}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Nix tmpfiles contract is missing ${required}")
    endif()
endforeach()
string(FIND "${cmake_source}" "install(DIRECTORY include/" found)
if(NOT found EQUAL -1)
    message(FATAL_ERROR "package must not expose daemon-internal headers")
endif()
foreach(required
        "Descolada <16986957+Descolada@users.noreply.github.com>"
        "CPACK_DEBIAN_PACKAGE_HOMEPAGE"
        "CPACK_DEBIAN_PACKAGE_PROVIDES \"keysharp-input-protocol-1.2\"")
    string(FIND "${cmake_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "package metadata is missing ${required}")
    endif()
endforeach()

foreach(required
        "keysharp-input-permissions.conf"
        "/usr/local/include/keysharp-inputd/protocol.h"
        "/usr/local/share/doc/keysharp-input/docs/protocol.md"
        "/usr/local/share/doc/keysharp-input/PROVENANCE.md"
        "/usr/local/lib/tmpfiles.d/keysharp-input-permissions.conf")
    string(FIND "${portable_uninstaller}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "portable uninstaller is missing ${required}")
    endif()
endforeach()

string(FIND "${debian_postinst}" "systemd-tmpfiles --create" found)
if(found EQUAL -1)
    message(FATAL_ERROR "Debian postinst does not create the shared-state directories")
endif()

foreach(required
        "/usr/local/bin/keysharp-inputd"
        "/usr/bin/keysharp-inputd"
        "/etc/systemd/system/keysharp-inputd.service"
        "/etc/systemd/system/keysharp-inputd.socket"
        "portable_binary_conflicts"
        "portable_service_conflicts"
        "portable_socket_conflicts"
        "/usr/local/share/doc/keysharp-input/uninstall.sh")
    string(FIND "${debian_preinst}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Debian preinst portable-layer guard is missing ${required}")
    endif()
endforeach()
foreach(required
        "foreach(script preinst postinst prerm postrm)"
        "KEYSHARP_INPUT_DEBIAN_CONTROLS")
    string(FIND "${cmake_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Debian package controls are missing ${required}")
    endif()
endforeach()

foreach(required
        "/var/lib/keysharp-permissions"
        "/run/keysharp-permissions")
    string(FIND "${service_unit}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "input service cannot write shared state ${required}")
    endif()
endforeach()
foreach(forbidden
        "StateDirectory=keysharp-permissions"
        "RuntimeDirectory=keysharp-permissions"
        "CMAKE_INSTALL_FULL_LIBDIR@/tmpfiles.d")
    string(FIND "${service_unit}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "input service must not contain ${forbidden}")
    endif()
endforeach()
foreach(forbidden
        "StateDirectory ="
        "RuntimeDirectory =")
    string(FIND "${nix_module}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "Nix service must not own shared state through ${forbidden}")
    endif()
endforeach()

foreach(lifecycle_source portable_uninstaller debian_postrm)
    string(REGEX MATCH
        "(rm|systemd-tmpfiles[ \t]+--remove)[^\n]*(/var/lib|/run)/keysharp-permissions"
        found "${${lifecycle_source}}")
    if(found)
        message(FATAL_ERROR "${lifecycle_source} must not purge shared permissions")
    endif()
endforeach()

foreach(required
        "project(keysharp-input"
        "DESCRIPTION \"Standalone privileged Linux input broker\""
        "KEYSHARP_INPUTD_TMPFILES_DIR"
        "KEYSHARP_INPUTD_TMPFILES_CONFIG"
        "KEYSHARP_INPUTD_NORMALIZED_PREFIX"
        "KEYSHARP_INPUTD_DEFAULT_SYSTEMD_UNIT_DIR \"/etc/systemd/system\""
        "KEYSHARP_INPUTD_DEFAULT_PACKAGED_UACCESS_RULE OFF"
        "KEYSHARP_INPUTD_INSTALL_PACKAGED_UACCESS_RULE"
        "include/keysharp_inputd/protocol.h"
        "DESTINATION \${CMAKE_INSTALL_INCLUDEDIR}/keysharp-inputd"
        "install(DIRECTORY docs/"
        "README.md LICENSE PROVENANCE.md"
        "/usr/share/polkit-1/actions")
    string(FIND "${cmake_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "source install polkit layout is missing ${required}")
    endif()
endforeach()
foreach(forbidden
        "/usr/local/lib/systemd/system"
        "/usr/local/lib/udev/rules.d")
    string(FIND "${portable_uninstaller}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "portable uninstall must not own stale source-install path ${forbidden}")
    endif()
endforeach()
string(FIND "${nix_package}"
    "-DKEYSHARP_INPUTD_POLKIT_ACTION_DIR=share/polkit-1/actions" found)
if(found EQUAL -1)
    message(FATAL_ERROR "Nix package must keep the polkit action in its output")
endif()

foreach(required
        "/etc/modules-load.d/keysharp-input.conf"
        "remove_owned_text_file"
        "KSI_LEGACY_UACCESS_RULES_CONTENTS"
        "KSI_PACKAGED_UACCESS_RULES_PATH")
    string(FIND "${main_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "input-access lifecycle is missing ${required}")
    endif()
endforeach()
string(FIND "${main_source}" "/etc/modules-load.d/uinput.conf" generic_modules_file)
if(NOT generic_modules_file EQUAL -1)
    message(FATAL_ERROR "input-access lifecycle must not own generic uinput.conf")
endif()

foreach(required
        "O_NOFOLLOW"
        "parent_chain_is_protected"
        "info.st_uid != owner"
        "S_IWGRP | S_IWOTH"
        "fchown(descriptor, owner, group)"
        "fchmod(descriptor, 0644)"
        "info.st_nlink != 1")
    string(FIND "${owned_text_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "owned setup configuration hardening is missing ${required}")
    endif()
endforeach()

foreach(required
        "KSI_PROTOCOL_MINOR 2u"
        "KSI_MESSAGE_REVOKE_PERMISSIONS"
        "persistent_scopes"
        "ksi_modifier_state_payload")
    string(FIND "${protocol_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "protocol 1.2 contract is missing ${required}")
    endif()
endforeach()
foreach(forbidden
        "RESET_PERMISSIONS"
        "persistent_denied_capabilities"
        "KSI_CLIENT_HELLO_FLAG_FORCE_PROMPT")
    string(FIND "${protocol_source}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "unexpected protocol surface remains: ${forbidden}")
    endif()
endforeach()
foreach(required
        "input-monitoring"
        "input-control"
        "strcmp(argv[0], \"revoke\")")
    string(FIND "${permissions_cli_source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "canonical permission CLI surface is missing ${required}")
    endif()
endforeach()
foreach(forbidden "--caps" "strcmp(argv[0], \"reset\")" "strcmp(argv[0], \"trust\")")
    string(FIND "${permissions_cli_source}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "unexpected permission CLI surface remains: ${forbidden}")
    endif()
endforeach()
foreach(required
        "$(polkit.message)"
        "Grant Input Monitoring or Input Control")
    string(FIND "${polkit_policy}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "polkit consent UI contract is missing ${required}")
    endif()
endforeach()
