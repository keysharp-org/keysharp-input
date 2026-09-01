#define KSI_POLKIT_TIMEOUT_SECONDS 120u

_Static_assert(KSI_POLKIT_TIMEOUT_SECONDS > 0u
        && KSI_POLKIT_TIMEOUT_SECONDS <= 3600u,
    "polkit timeout must satisfy the shared permission contract");

typedef struct ksi_identify_task {
    ksi_daemon_command_queue *commands;
    pid_t pid;
    uid_t uid;
    uint64_t start_time;
    int client_fd;
    uint64_t connection_id;
} ksi_identify_task;

typedef struct ksi_prompt_task {
    ksi_daemon_command_queue *commands;
    ksp_store *permissions;
    int client_fd;
    uint64_t connection_id;
    uint32_t requested_scopes;
    uint32_t missing_scopes;
    ksp_identity identity;
} ksi_prompt_task;

static void *identify_worker(void *arg)
{
    ksi_identify_task *task = arg;
    ksi_daemon_command command;
    ksi_client_identified_result *result;

    result = calloc(1, sizeof(*result));

    if (result != NULL) {
        ksp_identity identity;
        result->has_identity = ksp_identity_identify(
            task->pid, task->uid, task->start_time, &identity) == 0;
        if (result->has_identity) {
            (void)snprintf(result->exe_path, sizeof(result->exe_path),
                "%s", identity.executable);
            (void)snprintf(result->exe_hash, sizeof(result->exe_hash),
                "%s", identity.hash);
            result->start_time = identity.start_time;
        }
    }

    memset(&command, 0, sizeof(command));
    command.type = KSI_DAEMON_COMMAND_CLIENT_IDENTIFIED;
    command.client_fd = task->client_fd;
    command.connection_id = task->connection_id;
    command.data.identified.result = result;

    if (!ksi_pipe_ring_push(&task->commands->ring, &command)) {
        free(result);
    }

    free(task);
    return NULL;
}

static bool start_identify_task(
    ksi_daemon_command_queue *commands,
    pid_t pid,
    uid_t uid,
    uint64_t start_time,
    int client_fd,
    uint64_t connection_id)
{
    ksi_identify_task *task;
    task = malloc(sizeof(*task));

    if (task == NULL) {
        return false;
    }

    task->commands = commands;
    task->pid = pid;
    task->uid = uid;
    task->start_time = start_time;
    task->client_fd = client_fd;
    task->connection_id = connection_id;

    if (!ksi_worker_pool_submit(&g_identify_worker_pool, identify_worker, free, task)) {
        free(task);
        return false;
    }

    return true;
}

static void *prompt_worker(void *arg)
{
    ksi_prompt_task *task = arg;
    ksi_daemon_command command;
    uint32_t allowed = 0u;
    uint32_t missing = task->missing_scopes;
    uint64_t generation = 0u;
    int prompt_lock_fd;

    memset(&command, 0, sizeof(command));
    command.type = KSI_DAEMON_COMMAND_CLIENT_PROMPT_DONE;
    command.client_fd = task->client_fd;
    command.connection_id = task->connection_id;
    command.data.prompt_done.prompt_lock_fd = -1;
    prompt_lock_fd = ksp_prompt_lock_acquire(
        task->permissions, task->identity.uid, task->identity.hash,
        permissions_cancelled, NULL);

    if (prompt_lock_fd < 0) {
        command.data.prompt_done.decision = KSP_POLKIT_UNAVAILABLE;
    } else {
        command.data.prompt_done.prompt_lock_fd = prompt_lock_fd;
        command.data.prompt_done.prompt_lock_held = true;
        if (ksp_store_check_at_generation(
                task->permissions, task->identity.uid, task->identity.hash,
                task->missing_scopes, &allowed, &generation) != 0) {
            command.data.prompt_done.decision = KSP_POLKIT_UNAVAILABLE;
        } else {
            missing &= ~allowed;
            command.data.prompt_done.decision = missing == 0u
                ? KSP_POLKIT_GRANTED
                : ksp_polkit_authorize(
                    &(ksp_polkit_config) {
                        .pkcheck_path = KSI_PKCHECK_PATH,
                        .action_id = "org.keysharp.input.grant",
                        .scope_detail_key = "input.permissions",
                        .scope_names_detail_key = "input.permission-names",
                        .allowed_scopes = KSP_SCOPE_INPUT_MONITORING
                            | KSP_SCOPE_INPUT_CONTROL,
                        .timeout_seconds = KSI_POLKIT_TIMEOUT_SECONDS,
                    },
                    &task->identity, missing, permissions_cancelled, NULL);
        }
    }
    command.data.prompt_done.requested_scopes = task->requested_scopes;
    command.data.prompt_done.missing_scopes = missing;
    command.data.prompt_done.store_generation = generation;

    if (!ksi_pipe_ring_push(&task->commands->ring, &command)
        && command.data.prompt_done.prompt_lock_held) {
        ksp_prompt_lock_release(command.data.prompt_done.prompt_lock_fd);
    }
    free(task);
    return NULL;
}

static bool start_prompt_task(
    ksi_daemon_command_queue *commands,
    ksp_store *permissions,
    int client_fd,
    uint64_t connection_id,
    uint32_t requested,
    uint32_t missing,
    const char *exe_path,
    const char *exe_hash,
    pid_t pid,
    uid_t uid,
    uint64_t start_time)
{
    ksi_prompt_task *task;
    task = malloc(sizeof(*task));

    if (task == NULL) {
        return false;
    }

    task->commands = commands;
    task->permissions = permissions;
    task->client_fd = client_fd;
    task->connection_id = connection_id;
    task->requested_scopes = requested;
    task->missing_scopes = missing;
    memset(&task->identity, 0, sizeof(task->identity));
    task->identity.pid = pid;
    task->identity.uid = uid;
    task->identity.start_time = start_time;
    (void)snprintf(task->identity.executable,
        sizeof(task->identity.executable), "%s",
        exe_path != NULL ? exe_path : "");
    (void)snprintf(task->identity.hash, sizeof(task->identity.hash), "%s",
        exe_hash != NULL ? exe_hash : "");

    if (!ksi_worker_pool_submit(&g_worker_pool, prompt_worker, free, task)) {
        free(task);
        return false;
    }

    return true;
}

/* --- End async workers --- */
