typedef struct ksi_identify_task {
    ksi_daemon_command_queue *commands;
    pid_t pid;
    int client_fd;
    uint64_t connection_id;
} ksi_identify_task;

typedef struct ksi_prompt_task {
    ksi_daemon_command_queue *commands;
    ksi_auth_store *permissions;
    int client_fd;
    uint64_t connection_id;
    uint32_t requested_capabilities;
    uint32_t missing_scopes;
    uint32_t available_capabilities_at_start;
    char exe_path[KSI_AUTH_MAX_PATH];
    char exe_hash[KSI_AUTH_HASH_HEX_LENGTH + 1u];
    pid_t pid;
    uid_t uid;
    uint64_t start_time;
} ksi_prompt_task;

static void *identify_worker(void *arg)
{
    ksi_identify_task *task = arg;
    ksi_daemon_command command;
    ksi_client_identified_result *result;

    result = calloc(1, sizeof(*result));

    if (result != NULL) {
        result->has_identity = ksi_auth_identify_process(
            task->pid,
            result->exe_path, sizeof(result->exe_path),
            result->exe_hash) == 0;
        result->start_time = ksi_auth_get_process_start_time(task->pid);
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
    prompt_lock_fd = ksi_auth_prompt_lock_acquire(
        task->permissions, task->uid, task->exe_hash);

    if (prompt_lock_fd < 0) {
        command.data.prompt_done.decision = KSI_AUTH_UNAVAILABLE;
    } else {
        command.data.prompt_done.prompt_lock_fd = prompt_lock_fd;
        command.data.prompt_done.prompt_lock_held = true;
        if (ksi_auth_store_get_allowed_at_generation(
                task->permissions, task->uid, task->exe_hash,
                &allowed, &generation) != 0) {
            command.data.prompt_done.decision = KSI_AUTH_UNAVAILABLE;
        } else {
            missing &= ~allowed;
            command.data.prompt_done.decision = missing == 0u
                ? KSI_AUTH_GRANTED
                : ksi_auth_request_polkit(
                    task->pid, task->uid, task->start_time,
                    task->exe_path, task->exe_hash, missing);
        }
    }
    command.data.prompt_done.requested_capabilities = task->requested_capabilities;
    command.data.prompt_done.missing_scopes = missing;
    command.data.prompt_done.store_generation = generation;
    command.data.prompt_done.available_capabilities_at_start = task->available_capabilities_at_start;

    if (!ksi_pipe_ring_push(&task->commands->ring, &command)
        && command.data.prompt_done.prompt_lock_held) {
        close(command.data.prompt_done.prompt_lock_fd);
    }
    free(task);
    return NULL;
}

static bool start_prompt_task(
    ksi_daemon_command_queue *commands,
    ksi_auth_store *permissions,
    int client_fd,
    uint64_t connection_id,
    uint32_t requested,
    uint32_t missing,
    uint32_t available_capabilities_at_start,
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
    task->requested_capabilities = requested;
    task->missing_scopes = missing;
    task->available_capabilities_at_start = available_capabilities_at_start;
    (void)snprintf(task->exe_path, sizeof(task->exe_path), "%s", exe_path != NULL ? exe_path : "");
    (void)snprintf(task->exe_hash, sizeof(task->exe_hash), "%s", exe_hash != NULL ? exe_hash : "");
    task->pid = pid;
    task->uid = uid;
    task->start_time = start_time;

    if (!ksi_worker_pool_submit(&g_worker_pool, prompt_worker, free, task)) {
        free(task);
        return false;
    }

    return true;
}

/* --- End async workers --- */
