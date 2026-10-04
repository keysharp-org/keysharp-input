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
    ksi_daemon_state *state;
    ksi_hook_send_ref *send_ref;
    uint64_t input_generation;
    uint64_t permission_generation;
    uint64_t deadline_ms;
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

    if (result != NULL)
        result->has_identity = ksp_identity_identify(task->pid, task->uid,
            task->start_time, &result->identity) == 0;

    memset(&command, 0, sizeof(command));
    command.type = KSI_DAEMON_COMMAND_CLIENT_IDENTIFIED;
    command.client_fd = task->client_fd;
    command.connection_id = task->connection_id;
    command.data.identified.result = result;

    if (!ksi_pipe_ring_push(&task->commands->ring, &command)) free(result);

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
    task = calloc(1u, sizeof(*task));

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

static bool prompt_cancelled(void *context)
{
    ksi_prompt_task *task = context;
    return permissions_cancelled(NULL) || !hook_send_ref_is_valid(task->send_ref)
        || !input_owner_matches_uid(task->state, task->identity.uid)
        || current_input_generation(task->state) != task->input_generation
        || atomic_load(&task->state->permission_generation) != task->permission_generation
        || monotonic_ms() >= task->deadline_ms;
}

static bool prompt_commit_cancelled(void *context)
{
    ksi_prompt_task *task = context;
    ksp_identity verified;
    return prompt_cancelled(task)
        || ksp_identity_revalidate_cached(&task->identity, &verified) != 0;
}

static void free_prompt_task(void *context)
{
    ksi_prompt_task *task = context;
    hook_send_ref_release(task->send_ref);
    free(task);
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
        prompt_cancelled, task);

    if (prompt_lock_fd < 0) {
        command.data.prompt_done.decision = KSP_POLKIT_UNAVAILABLE;
    } else {
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
                    &task->identity, missing, prompt_cancelled, task);
        }
        if (command.data.prompt_done.decision == KSP_POLKIT_GRANTED
            && missing != 0u) {
            int result = ksp_store_grant_if_generation_cancelled(task->permissions,
                &task->identity, missing, generation, prompt_commit_cancelled, task);
            if (result != 0) command.data.prompt_done.decision = KSP_POLKIT_DENIED;
        }
        if (prompt_commit_cancelled(task)
            || ksp_store_check_at_generation(task->permissions, task->identity.uid,
                task->identity.hash, KSI_INPUT_PERMISSION_SCOPES, &allowed, &generation) != 0) {
            allowed = 0u;
            command.data.prompt_done.decision = KSP_POLKIT_DENIED;
        }
        ksp_prompt_lock_release(prompt_lock_fd);
    }
    command.data.prompt_done.requested_scopes = task->requested_scopes;
    command.data.prompt_done.missing_scopes = missing;
    command.data.prompt_done.store_generation = generation;
    command.data.prompt_done.allowed_scopes = allowed;
    command.data.prompt_done.permission_generation = task->permission_generation;
    command.data.prompt_done.input_generation = task->input_generation;

    if (!ksi_pipe_ring_push(&task->commands->ring, &command)
        && command.data.prompt_done.prompt_lock_held) {
        ksp_prompt_lock_release(command.data.prompt_done.prompt_lock_fd);
    }
    free_prompt_task(task);
    return NULL;
}

static bool start_prompt_task(
    ksi_daemon_state *state,
    ksi_hook_send_ref *send_ref,
    ksi_daemon_command_queue *commands,
    ksp_store *permissions,
    int client_fd,
    uint64_t connection_id,
    uint32_t requested,
    uint32_t missing,
    const ksp_identity *identity)
{
    ksi_prompt_task *task;
    task = malloc(sizeof(*task));

    if (task == NULL) {
        return false;
    }

    task->commands = commands;
    if (!hook_send_ref_acquire(send_ref)) {
        free(task);
        return false;
    }
    task->state = state;
    task->send_ref = send_ref;
    task->input_generation = current_input_generation(state);
    task->permission_generation = atomic_load(&state->permission_generation);
    task->deadline_ms = monotonic_ms() + KSI_AUTHORIZATION_TIMEOUT_MS;
    task->permissions = permissions;
    task->client_fd = client_fd;
    task->connection_id = connection_id;
    task->requested_scopes = requested;
    task->missing_scopes = missing;
    task->identity = *identity;

    if (!ksi_worker_pool_submit(&g_worker_pool, prompt_worker, free_prompt_task, task)) {
        free_prompt_task(task);
        return false;
    }

    return true;
}

/* --- End async workers --- */
