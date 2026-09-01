#include "internal/daemon.h"
#include "keysharp_input/client.h"
#include "owned_text_file.h"

int permissions_cli_main(int argc, char **argv);

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

bool g_verbose = false;

#define KSI_DEFAULT_SOCKET_DIR_NAME "keysharp-input"
#define KSI_DEFAULT_SOCKET_NAME "keysharp-input.sock"
#define KSI_SOCKET_PATH_LENGTH 256

#define KSI_SETUP_FILE_ERROR 1
#define KSI_SETUP_LIVE_ERROR 2

static const char *const KSI_MODPROBE_PATHS[] = {
	"/usr/sbin/modprobe", "/sbin/modprobe", NULL
};
static const char *const KSI_UDEVADM_PATHS[] = {
	"/usr/bin/udevadm", "/usr/sbin/udevadm", "/bin/udevadm", "/sbin/udevadm", NULL
};
static const char *const KSI_SYSTEMCTL_PATHS[] = {
	"/usr/bin/systemctl", "/bin/systemctl", NULL
};

static const char *find_trusted_program(const char *const paths[])
{
	for (size_t i = 0u; paths[i] != NULL; i++) {
		if (access(paths[i], X_OK) == 0) {
			return paths[i];
		}
	}

	return NULL;
}

static int run_trusted_program(const char *path, char *const argv[])
{
	pid_t child;
	pid_t waited;
	int status;

	if (path == NULL) {
		return 127;
	}

	child = fork();

	if (child < 0) {
		return 126;
	}

	if (child == 0) {
		if (clearenv() != 0
			|| setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0
			|| setenv("LANG", "C", 1) != 0) {
			_exit(126);
		}

		execv(path, argv);
		_exit(errno == ENOENT ? 127 : 126);
	}

	do {
		status = 0;
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);

	if (waited < 0) {
		return 126;
	}

	if (WIFEXITED(status)) {
		return WEXITSTATUS(status);
	}

	return 126;
}

/* Shared by install/remove so the two paths always agree on the file to manage.
 * Numbered 70- so it lexically precedes systemd's 73-seat-late.rules, which runs
 * the uaccess builtin; a tag added after that rule would have no effect. */
#define KSI_UACCESS_RULES_PATH "/etc/udev/rules.d/70-keysharp-input-uaccess.rules"
#define KSI_PACKAGED_UACCESS_RULES_PATH "/usr/lib/udev/rules.d/70-keysharp-input-uaccess.rules"
/* Remove this exact known unsafe rule only when its contents also match. */
#define KSI_LEGACY_INSECURE_UACCESS_RULES_PATH "/etc/udev/rules.d/99-keysharp-inputd.rules"

/* uinput module auto-load config written by --install-input-access. Shared with
 * --remove-input-access so removal cleans up exactly what install created and the
 * two paths cannot drift. */
#define KSI_UINPUT_MODULES_PATH "/etc/modules-load.d/keysharp-input.conf"
#define KSI_UINPUT_MODULES_CONTENTS "uinput\n"

static int ensure_private_directory(const char *path)
{
    struct stat info;

    if (mkdir(path, S_IRWXU) != 0 && errno != EEXIST) {
        fprintf(stderr, "failed to create socket directory %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (stat(path, &info) != 0) {
        fprintf(stderr, "failed to stat socket directory %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (!S_ISDIR(info.st_mode)) {
        fprintf(stderr, "socket path parent is not a directory: %s\n", path);
        return -1;
    }

    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0 && chmod(path, S_IRWXU) != 0) {
        fprintf(stderr, "failed to chmod socket directory %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

static int build_default_socket_path(char *buffer, size_t buffer_size)
{
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    char directory[KSI_SOCKET_PATH_LENGTH];

    if (runtime_dir == NULL || runtime_dir[0] == '\0') {
        fprintf(stderr, "XDG_RUNTIME_DIR is not set; use --socket PATH to override\n");
        return -1;
    }

    if (snprintf(directory, sizeof(directory), "%s/%s", runtime_dir, KSI_DEFAULT_SOCKET_DIR_NAME)
        >= (int)sizeof(directory)) {
        fprintf(stderr, "default socket directory path is too long\n");
        return -1;
    }

    if (ensure_private_directory(directory) != 0) {
        return -1;
    }

    if (snprintf(buffer, buffer_size, "%s/%s", directory, KSI_DEFAULT_SOCKET_NAME)
        >= (int)buffer_size) {
        fprintf(stderr, "default socket path is too long\n");
        return -1;
    }

    return 0;
}

static void print_usage(const char *argv0)
{
	printf(
		"Usage: %s <command> [options]\n\n"
		"Commands:\n"
		"  version                 Print the product version.\n"
		"  info                    Print static machine-readable metadata.\n"
		"  probe [--socket PATH]   Check a running service.\n"
		"  daemon [options]        Run or configure the service.\n"
		"  permissions <command>   List or revoke permission grants.\n",
		argv0);
}

/* Body of the uaccess udev rule written by --install-input-access.
 * The broker grabs physical devices and re-emits passed events through its
 * uinput devices, so the active session's X/Wayland consumer needs read access
 * to those virtual event nodes. Matching their unique names avoids granting
 * access to unrelated input devices or keyd devices which share the vendor id.
 * ATTRS{} finds the parent input-device name while the tag remains on the event
 * node consumed by the uaccess builtin. */
static const char KSI_UACCESS_RULES_CONTENTS[] =
	"# Grants the active-session user an ACL on the broker's virtual devices.\n"
	"# Replayed events are then readable by the session's X/Wayland consumer.\n"
	"ACTION!=\"add|change\", GOTO=\"keysharp_uaccess_end\"\n"
	"SUBSYSTEM!=\"input\", GOTO=\"keysharp_uaccess_end\"\n"
	"\n"
	"ATTRS{name}==\"Keysharp Virtual Input\", TAG+=\"uaccess\"\n"
	"ATTRS{name}==\"Keysharp Virtual Pointer\", TAG+=\"uaccess\"\n"
	"\n"
	"LABEL=\"keysharp_uaccess_end\"\n";

static const char KSI_INSECURE_UACCESS_RULES_CONTENTS[] =
	"KERNEL==\"event*\", SUBSYSTEM==\"input\", GROUP=\"input\", MODE=\"0660\"\n"
	"KERNEL==\"uinput\", SUBSYSTEM==\"misc\", GROUP=\"input\", MODE=\"0660\", OPTIONS+=\"static_node=uinput\"\n";

static bool file_matches_text(const char *path, const char *contents)
{
	const unsigned char *current = (const unsigned char *)contents;
	FILE *file = fopen(path, "rb");
	int value;

	if (file == NULL) {
		return false;
	}

	while (*current != '\0') {
		value = fgetc(file);

		if (value == EOF || (unsigned char)value != *current) {
			(void)fclose(file);
			return false;
		}

		current++;
	}

	value = fgetc(file);
	(void)fclose(file);
	return value == EOF;
}

static int ensure_owned_text_file(const char *path, const char *contents)
{
	if (ksi_ensure_owned_text_file(path, contents, 0, 0, "/") == 0) {
		return 0;
	}

	fprintf(stderr, "refusing unsafe or modified configuration %s: %s\n",
		path, strerror(errno));
	return -1;
}

static int remove_owned_text_file(const char *path, const char *contents)
{
	struct stat info;

	if (lstat(path, &info) != 0) {
		return errno == ENOENT ? 0 : -1;
	}

	if (!S_ISREG(info.st_mode) || !file_matches_text(path, contents)) {
		fprintf(stderr, "notice: keeping modified or unowned configuration %s\n", path);
		return 0;
	}

	return unlink(path);
}

static int install_input_access(void)
{
	const char *modules_path = KSI_UINPUT_MODULES_PATH;
	const char *modprobe_path = find_trusted_program(KSI_MODPROBE_PATHS);
	const char *udevadm_path = find_trusted_program(KSI_UDEVADM_PATHS);
	const char *systemctl_path = find_trusted_program(KSI_SYSTEMCTL_PATHS);
	int status = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "--install-input-access must be run as root\n");
		return 1;
	}

	if (ensure_owned_text_file(modules_path, KSI_UINPUT_MODULES_CONTENTS) != 0) {
		status |= KSI_SETUP_FILE_ERROR;
	}

	{
		char *const args[] = { "modprobe", "uinput", NULL };

		if (run_trusted_program(modprobe_path, args) != 0) {
			fprintf(stderr, "warning: modprobe uinput failed\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}
	}

	if (remove_owned_text_file(KSI_LEGACY_INSECURE_UACCESS_RULES_PATH,
		KSI_INSECURE_UACCESS_RULES_CONTENTS) != 0) {
		fprintf(stderr, "warning: failed to remove unsafe rule %s: %s\n",
			KSI_LEGACY_INSECURE_UACCESS_RULES_PATH, strerror(errno));
		status |= KSI_SETUP_FILE_ERROR;
	}

	/* Grant the consuming X/Wayland server read access to the daemon's own
	 * virtual devices via systemd-logind's uaccess ACL (see the rationale on
	 * KSI_UACCESS_RULES_CONTENTS above). */
	if (access(KSI_PACKAGED_UACCESS_RULES_PATH, R_OK) == 0) {
		if (file_matches_text(KSI_UACCESS_RULES_PATH, KSI_UACCESS_RULES_CONTENTS)) {
			if (unlink(KSI_UACCESS_RULES_PATH) != 0) {
				fprintf(stderr, "failed to remove redundant %s: %s\n",
					KSI_UACCESS_RULES_PATH, strerror(errno));
				status |= KSI_SETUP_FILE_ERROR;
			}
		} else if (access(KSI_UACCESS_RULES_PATH, F_OK) == 0) {
			fprintf(stderr, "notice: keeping administrator override %s\n", KSI_UACCESS_RULES_PATH);
		}
	} else if (ensure_owned_text_file(KSI_UACCESS_RULES_PATH,
		KSI_UACCESS_RULES_CONTENTS) != 0) {
		status |= KSI_SETUP_FILE_ERROR;
	}

	/* Reload rules and re-trigger so the new uaccess tag is applied to any
	 * already-present virtual devices as well as future ones. */
	{
		char *const reload_args[] = { "udevadm", "control", "--reload-rules", NULL };
		char *const input_args[] = { "udevadm", "trigger", "--subsystem-match=input", NULL };
		char *const misc_args[] = { "udevadm", "trigger", "--subsystem-match=misc", NULL };

		if (run_trusted_program(udevadm_path, reload_args) != 0
			|| run_trusted_program(udevadm_path, input_args) != 0
			|| run_trusted_program(udevadm_path, misc_args) != 0) {
			fprintf(stderr, "warning: failed to refresh udev after installing the uaccess rule\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}
	}

	/* Replace any stale daemon: reload unit definitions, stop both halves of the
	 * socket-activated service, then enable only the service and start it.  The
	 * service's Requires= dependency starts the socket, so enabling
	 * the socket separately only creates a redundant second boot symlink; it does
	 * not create a second IPC endpoint.  Explicitly disabling the socket target
	 * also cleans up that redundant symlink on upgrades from older installs.
	 * The service remains resident from boot so its idle counter has continuity
	 * even when no client process is connected. Once started, the socket stays
	 * available as the daemon's recovery activation path.
	 * Tolerate systemctl being absent (e.g. non-systemd hosts): warn, do not
	 * hard-fail; the udev/uinput setup above is still useful without it. */
	if (systemctl_path == NULL) {
		/* Benign on non-systemd hosts: the udev/uinput setup above is the part
		 * that actually fixes input access, so don't fail the whole command (and
		 * trigger the installer's scary "did not complete" banner) just for this. */
		fprintf(stderr, "notice: systemctl not found; skipping service activation refresh\n");
	} else {
		char *const reload_args[] = { "systemctl", "daemon-reload", NULL };
		char *const stop_args[] = {
			"systemctl", "stop", "keysharp-input.service", "keysharp-input.socket", NULL
		};
		char *const disable_args[] = {
			"systemctl", "disable", "keysharp-input.socket", NULL
		};
		char *const enable_args[] = {
			"systemctl", "enable", "--now", "keysharp-input.service", NULL
		};

		if (run_trusted_program(systemctl_path, reload_args) != 0) {
			fprintf(stderr, "warning: systemctl daemon-reload failed\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}

		/* Stopping inactive/absent units can exit non-zero on older systemd;
		 * that's benign here because the service start below recreates the pair. */
		if (run_trusted_program(systemctl_path, stop_args) != 0) {
			fprintf(stderr, "notice: keysharp-input units were not running (nothing to stop)\n");
		}

		if (run_trusted_program(systemctl_path, disable_args) != 0) {
			fprintf(stderr, "warning: failed to remove redundant keysharp-input.socket boot enablement\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}

		if (run_trusted_program(systemctl_path, enable_args) != 0) {
			fprintf(stderr, "warning: failed to enable and start keysharp-input.service\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}
	}

	if (status == 0) {
		puts("keysharp-input input access setup complete.");
	}
	return status;
}

/* Remove the uaccess rule installed by --install-input-access and reload udev.
 * Exposed as its own flag so the uninstaller script can call it. Mirrors the
 * defensive style of install_input_access: warn + set status, never abort. */
static int remove_input_access(void)
{
	const char *udevadm_path = find_trusted_program(KSI_UDEVADM_PATHS);
	int status = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "--remove-input-access must be run as root\n");
		return 1;
	}

	if (remove_owned_text_file(KSI_UACCESS_RULES_PATH, KSI_UACCESS_RULES_CONTENTS) != 0) {
		fprintf(stderr, "warning: failed to remove %s: %s\n", KSI_UACCESS_RULES_PATH, strerror(errno));
		status |= KSI_SETUP_FILE_ERROR;
	}

	/* Also remove the uinput module-load config install wrote, so removal does
	 * not leave the kernel auto-loading the uinput module every boot. */
	if (remove_owned_text_file(KSI_UINPUT_MODULES_PATH, KSI_UINPUT_MODULES_CONTENTS) != 0) {
		fprintf(stderr, "warning: failed to remove %s: %s\n", KSI_UINPUT_MODULES_PATH, strerror(errno));
		status |= KSI_SETUP_FILE_ERROR;
	}

	{
		char *const reload_args[] = { "udevadm", "control", "--reload-rules", NULL };
		char *const input_args[] = { "udevadm", "trigger", "--subsystem-match=input", NULL };

		if (run_trusted_program(udevadm_path, reload_args) != 0
			|| run_trusted_program(udevadm_path, input_args) != 0) {
			fprintf(stderr, "warning: failed to refresh udev after removing the uaccess rule\n");
			status |= KSI_SETUP_LIVE_ERROR;
		}
	}

	puts("keysharp-input uaccess rule removed.");
	return status;
}

static int validate_systemd_socket_activation(void)
{
	const char *listen_pid = getenv("LISTEN_PID");
	const char *listen_fds = getenv("LISTEN_FDS");
	char *end = NULL;
	long pid_value;

	if (geteuid() != 0 || listen_pid == NULL || listen_fds == NULL || strcmp(listen_fds, "1") != 0) {
		fprintf(stderr, "--system-service requires one systemd socket and root service context\n");
		return -1;
	}

	errno = 0;
	pid_value = strtol(listen_pid, &end, 10);

	if (errno != 0 || end == listen_pid || *end != '\0' || pid_value != (long)getpid()) {
		fprintf(stderr, "--system-service LISTEN_PID does not match this daemon\n");
		return -1;
	}

	unsetenv("LISTEN_PID");
	unsetenv("LISTEN_FDS");
	unsetenv("LISTEN_FDNAMES");
	return 0;
}

static int probe_main(int argc, char **argv)
{
    ksi_connect_options options;
    ksi_service_info info;
    ksi_error error;
    ksi_connection *connection = NULL;

    ksi_connect_options_init(&options);
    ksi_service_info_init(&info);
    ksi_error_init(&error);
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            options.socket_path = argv[++i];
        } else {
            fprintf(stderr, "probe: unexpected argument: %s\n", argv[i]);
            return 2;
        }
    }
    ksi_status status = ksi_connect(&options, &connection, &info, &error);
    if (status != KSI_STATUS_OK) {
        fprintf(stderr, "probe: %s\n",
            error.message[0] == '\0' ? "service is unavailable" : error.message);
        return 1;
    }
    printf("service_status=ready\n");
    printf("granted_scopes=0x%08x\n", info.granted_scopes);
    printf("available_operations=0x%016llx\n",
        (unsigned long long)info.available_operations);
    ksi_disconnect(connection);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc == 1 || strcmp(argv[1], "help") == 0
        || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        if (argc > 2) {
            fprintf(stderr, "help: too many arguments\n");
            return 2;
        }
        print_usage(argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "version") == 0) {
        if (argc != 2) {
            fprintf(stderr, "version: no arguments are accepted\n");
            return 2;
        }
        printf("%s %s\n", ksi_client_product_name(),
            ksi_client_product_version());
        return 0;
    }
    if (strcmp(argv[1], "info") == 0) {
        if (argc != 2) {
            fprintf(stderr, "info: no arguments are accepted\n");
            return 2;
        }
		printf("product_name=%s\n", ksi_client_product_name());
		printf("product_version=%s\n", ksi_client_product_version());
		printf("client_abi_major=%u\n", ksi_client_abi_major());
		printf("client_abi_minor=%u\n", ksi_client_abi_minor());
        printf("permission_store_version=1\n");
        printf("socket=%s\n", KSI_DEFAULT_SOCKET_PATH);
        printf("service_scope=system\n");
        printf("activation=systemd-socket\n");
        return 0;
    }
    if (strcmp(argv[1], "probe") == 0) {
        return probe_main(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "permissions") == 0) {
        return permissions_cli_main(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "daemon") != 0) {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 2;
    }

    char default_socket_path[KSI_SOCKET_PATH_LENGTH];
    ksi_daemon_options options = {
        .socket_path = NULL,
        .foreground = true,
        .system_service = false,
    };
    bool socket_path_overridden = false;
    bool daemon_option_seen = false;
    int maintenance_action = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0) {
            options.foreground = true;
            daemon_option_seen = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_verbose = true;
			daemon_option_seen = true;
		} else if (strcmp(argv[i], "--socket") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--socket requires a path\n");
				return 2;
			}

			options.socket_path = argv[++i];
			socket_path_overridden = true;
			daemon_option_seen = true;
		} else if (strcmp(argv[i], "--system-service") == 0) {
			options.system_service = true;
			daemon_option_seen = true;
		} else if (strcmp(argv[i], "--install-input-access") == 0) {
			if (maintenance_action != 0) {
				fprintf(stderr, "daemon: choose one maintenance action\n");
				return 2;
			}
			maintenance_action = 1;
		} else if (strcmp(argv[i], "--remove-input-access") == 0) {
			if (maintenance_action != 0) {
				fprintf(stderr, "daemon: choose one maintenance action\n");
				return 2;
			}
			maintenance_action = 2;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            if (argc != 3) {
                fprintf(stderr, "daemon: help cannot be combined with options\n");
                return 2;
            }
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "daemon: unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (maintenance_action != 0) {
        if (daemon_option_seen) {
            fprintf(stderr, "daemon: maintenance actions cannot be combined with runtime options\n");
            return 2;
        }
        return maintenance_action == 1
            ? install_input_access() : remove_input_access();
    }

    if (options.system_service) {
        if (socket_path_overridden) {
            fprintf(stderr, "--socket cannot be combined with --system-service\n");
            return 2;
        }

        if (validate_systemd_socket_activation() != 0) {
            return 2;
        }
    } else if (!socket_path_overridden) {
        if (build_default_socket_path(default_socket_path, sizeof(default_socket_path)) != 0) {
            return 2;
        }

        options.socket_path = default_socket_path;
    }

    return ksi_daemon_run(&options);
}
