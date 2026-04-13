/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    bounded_buffer_t *buffer = (bounded_buffer_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(buffer, &item) == 0) {
        char log_path[PATH_MAX];
        snprintf(log_path, sizeof(log_path), "%s/%s.log",
                 LOG_DIR, item.container_id);

        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, item.data, item.length);
            close(fd);
        }
    }
    return NULL;
}
/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg) {
    child_config_t *cfg = (child_config_t *)arg;
    
    // 1. Set hostname to container ID (UTS namespace)
    sethostname(cfg->id, strlen(cfg->id));
    
    // 2. chroot into container's rootfs
    chroot(cfg->rootfs);
    chdir("/");
    
    // 3. Mount /proc so ps, top etc work
    mount("proc", "/proc", "proc", 0, NULL);
    
    // 4. Redirect stdout/stderr to log pipe
    dup2(cfg->log_write_fd, STDOUT_FILENO);
    dup2(cfg->log_write_fd, STDERR_FILENO);
    close(cfg->log_write_fd);
    
    // 5. Set nice value
    setpriority(PRIO_PROCESS, 0, cfg->nice_value);
    
    // 6. exec the command
    char *args[] = {cfg->command, NULL};
    execv(cfg->command, args);
    
    // if exec fails
    perror("execv");
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */

typedef struct {
    pid_t pid;
    int read_fd;
    char log_path[PATH_MAX];
    container_record_t *record;
    pthread_mutex_t *lock;
} waiter_arg_t;

static void *container_waiter(void *arg)
{
    waiter_arg_t *w = (waiter_arg_t *)arg;
    
    // Read pipe and write to log file
    int log_fd = open(w->log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(w->read_fd, buf, sizeof(buf))) > 0)
            write(log_fd, buf, n);
        close(log_fd);
    }
    close(w->read_fd);

    // Reap child
    int status;
    waitpid(w->pid, &status, 0);
    
    pthread_mutex_lock(w->lock);
    w->record->state = CONTAINER_EXITED;
    if (WIFEXITED(status))
        w->record->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        w->record->exit_signal = WTERMSIG(status);
    pthread_mutex_unlock(w->lock);
    
    free(w);
    return NULL;
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;
    struct sockaddr_un addr;

    (void)rootfs;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    // 1. Open kernel monitor device
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr, "Warning: could not open /dev/container_monitor: %s\n",
                strerror(errno));
        // not fatal yet, continue without kernel monitor
    }

    // 2. Create UNIX domain socket
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        return 1;
    }

    unlink(CONTROL_PATH); // remove stale socket
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(ctx.server_fd);
        return 1;
    }

    if (listen(ctx.server_fd, 10) < 0) {
        perror("listen");
        close(ctx.server_fd);
        return 1;
    }

    // 3. Create log directory
    mkdir(LOG_DIR, 0755);

    fprintf(stdout, "Supervisor started. Listening on %s\n", CONTROL_PATH);
    fflush(stdout);

    // 4. Event loop - accept CLI connections
    while (!ctx.should_stop) {
        int client_fd;
        control_request_t req;
        control_response_t resp;

        client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        // Read request
        if (read(client_fd, &req, sizeof(req)) != sizeof(req)) {
            close(client_fd);
            continue;
        }

        memset(&resp, 0, sizeof(resp));

        if (req.kind == CMD_PS) {
            // List all containers
            pthread_mutex_lock(&ctx.metadata_lock);
            container_record_t *c = ctx.containers;
            char line[256];
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message),
                     "%-12s %-8s %-10s %s\n",
                     "ID", "PID", "STATE", "LOG");
            write(client_fd, &resp, sizeof(resp));
            while (c) {
                memset(&resp, 0, sizeof(resp));
                snprintf(line, sizeof(line),
                         "%-12s %-8d %-10s %s\n",
                         c->id, c->host_pid,
                         state_to_string(c->state),
                         c->log_path);
                snprintf(resp.message, sizeof(resp.message), "%s", line);
                write(client_fd, &resp, sizeof(resp));
                c = c->next;
            }
            pthread_mutex_unlock(&ctx.metadata_lock);
            close(client_fd);
            continue;
        }

        if (req.kind == CMD_LOGS) {
            pthread_mutex_lock(&ctx.metadata_lock);
            container_record_t *c = ctx.containers;
            while (c) {
                if (strcmp(c->id, req.container_id) == 0) {
                    // Read and send log file contents
                    FILE *f = fopen(c->log_path, "r");
                    if (f) {
                        char line[256];
                        while (fgets(line, sizeof(line), f)) {
                            memset(&resp, 0, sizeof(resp));
                            snprintf(resp.message, sizeof(resp.message), "%s", line);
                            resp.status = 0;
                            write(client_fd, &resp, sizeof(resp));
                        }
                        fclose(f);
                    } else {
                        snprintf(resp.message, sizeof(resp.message),
                                "No log file found for %s\n", req.container_id);
                        resp.status = 0;
                        write(client_fd, &resp, sizeof(resp));
                    }
                    pthread_mutex_unlock(&ctx.metadata_lock);
                    close(client_fd);
                    goto next_client;
                }
                c = c->next;
            }
            snprintf(resp.message, sizeof(resp.message),
                    "Container %s not found\n", req.container_id);
            resp.status = -1;
            write(client_fd, &resp, sizeof(resp));
            pthread_mutex_unlock(&ctx.metadata_lock);
            close(client_fd);
            continue;
        }

        if (req.kind == CMD_STOP) {
            pthread_mutex_lock(&ctx.metadata_lock);
            container_record_t *c = ctx.containers;
            while (c) {
                if (strcmp(c->id, req.container_id) == 0) {
                    kill(c->host_pid, SIGTERM);
                    c->state = CONTAINER_STOPPED;
                    snprintf(resp.message, sizeof(resp.message),
                             "Stopped container %s\n", c->id);
                    resp.status = 0;
                    break;
                }
                c = c->next;
            }
            if (resp.status != 0)
                snprintf(resp.message, sizeof(resp.message),
                         "Container %s not found\n", req.container_id);
            pthread_mutex_unlock(&ctx.metadata_lock);
            write(client_fd, &resp, sizeof(resp));
            close(client_fd);
            continue;
        }

        if (req.kind == CMD_START || req.kind == CMD_RUN) {
            // Allocate stack for clone
            char *stack = malloc(STACK_SIZE);
            if (!stack) {
                snprintf(resp.message, sizeof(resp.message), "Out of memory\n");
                resp.status = -1;
                write(client_fd, &resp, sizeof(resp));
                close(client_fd);
                continue;
            }

            // Set up child config
            child_config_t *cfg = malloc(sizeof(child_config_t));
            memset(cfg, 0, sizeof(*cfg));
            strncpy(cfg->id, req.container_id, sizeof(cfg->id) - 1);
            strncpy(cfg->rootfs, req.rootfs, sizeof(cfg->rootfs) - 1);
            strncpy(cfg->command, req.command, sizeof(cfg->command) - 1);
            cfg->nice_value = req.nice_value;
            cfg->log_write_fd = -1;

            // Create log file
            container_record_t *record = malloc(sizeof(container_record_t));
            memset(record, 0, sizeof(*record));
            strncpy(record->id, req.container_id, sizeof(record->id) - 1);
            snprintf(record->log_path, sizeof(record->log_path),
                     "%s/%s.log", LOG_DIR, req.container_id);
            record->soft_limit_bytes = req.soft_limit_bytes;
            record->hard_limit_bytes = req.hard_limit_bytes;
            record->state = CONTAINER_STARTING;
            record->started_at = time(NULL);

            // Create pipe for container output
            int pipefd[2];
            if (pipe(pipefd) < 0) {
                perror("pipe");
                free(stack); free(cfg); free(record);
                close(client_fd);
                continue;
            }
            cfg->log_write_fd = pipefd[1];

            // Launch container with clone()
            pid_t pid = clone(child_fn, stack + STACK_SIZE,
                              CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                              cfg);
            if (pid < 0) {
                perror("clone");
                free(stack); free(cfg); free(record);
                close(pipefd[0]); close(pipefd[1]);
                snprintf(resp.message, sizeof(resp.message),
                         "Failed to start container\n");
                resp.status = -1;
                write(client_fd, &resp, sizeof(resp));
                close(client_fd);
                continue;
            }

            close(pipefd[1]); // supervisor doesn't write to container

            record->host_pid = pid;
            record->state = CONTAINER_RUNNING;

            // Add to metadata list
            pthread_mutex_lock(&ctx.metadata_lock);
            // Check for duplicate ID
            container_record_t *existing = ctx.containers;
            int duplicate = 0;
            while (existing) {
                if (strcmp(existing->id, req.container_id) == 0) {
                    duplicate = 1;
                    break;
                }
                existing = existing->next;
            }
            if (duplicate) {
                snprintf(resp.message, sizeof(resp.message),
                        "Container %s already exists\n", req.container_id);
                resp.status = -1;
                write(client_fd, &resp, sizeof(resp));
                close(client_fd);
                free(stack); free(cfg); free(record);
                close(pipefd[0]); close(pipefd[1]);
                continue;
            }
            record->next = ctx.containers;
            ctx.containers = record;
            pthread_mutex_unlock(&ctx.metadata_lock);

            // Register with kernel monitor
            if (ctx.monitor_fd >= 0) {
                register_with_monitor(ctx.monitor_fd, req.container_id,
                                      pid, req.soft_limit_bytes,
                                      req.hard_limit_bytes);
            }

            snprintf(resp.message, sizeof(resp.message),
                     "Started container %s pid=%d\n", req.container_id, pid);
            resp.status = 0;
            write(client_fd, &resp, sizeof(resp));
            close(client_fd);

            // Spawn waiter thread so supervisor stays responsive
            waiter_arg_t *warg = malloc(sizeof(waiter_arg_t));
            warg->pid = pid;
            warg->read_fd = pipefd[0];
            warg->record = record;
            warg->lock = &ctx.metadata_lock;
            strncpy(warg->log_path, record->log_path, PATH_MAX - 1);

            pthread_t waiter;
            pthread_create(&waiter, NULL, container_waiter, warg);
            pthread_detach(waiter);
            pthread_mutex_lock(&ctx.metadata_lock);
            record->state = CONTAINER_EXITED;
            pthread_mutex_unlock(&ctx.metadata_lock);
            free(stack);
            free(cfg);
            continue;
        }

        // Unknown command
        snprintf(resp.message, sizeof(resp.message), "Unknown command\n");
        resp.status = -1;
        write(client_fd, &resp, sizeof(resp));
        close(client_fd);
        next_client:;
    }

    // Cleanup
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect - is supervisor running?");
        close(fd);
        return 1;
    }

    if (write(fd, req, sizeof(*req)) != sizeof(*req)) {
        perror("write");
        close(fd);
        return 1;
    }

    // Read and print response(s)
    while (read(fd, &resp, sizeof(resp)) == sizeof(resp)) {
        printf("%s", resp.message);
        if (resp.status != 0) {
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    /*
     * TODO:
     * The supervisor should respond with container metadata.
     * Keep the rendering format simple enough for demos and debugging.
     */
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
