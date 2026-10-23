/* MC7021 one-session capture helper. No installation, daemon or network writes.
 * Only fixed /usr/sbin/tcpdump starts privileged; supervisor drops privileges
 * before writing any user-controlled path. --self-test performs no capture.
 */
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#endif

#define STARTUP_SECONDS 12.0
#define HEARTBEAT_SECONDS 10.0
#define CAPTURE_SECONDS 900.0
#define LOG_CAPACITY (256 * 1024)

static volatile sig_atomic_t interrupted = 0;
static void on_signal(int value) { interrupted = value; }
static double monotonic_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (double)value.tv_sec + value.tv_nsec / 1000000000.0;
}
static int decimal(const char *s, unsigned long *value) {
    char *end = NULL;
    if (!s || !*s || strlen(s) > 10) return 0;
    for (const char *p = s; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
    errno = 0; *value = strtoul(s, &end, 10);
    return !errno && end && !*end && *value <= INT_MAX;
}
static int valid_interface(const char *s) {
    unsigned long value;
    return s && strncmp(s, "rvi", 3) == 0 && decimal(s + 3, &value) && value <= 999999;
}
static int valid_nonce(const char *s) {
    if (!s || strlen(s) != 32) return 0;
    for (const char *p = s; *p; ++p)
        if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) return 0;
    return 1;
}
static int valid_ip(const char *s) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!s || strchr(s, '%')) return 0;
    if (inet_pton(AF_INET, s, &v4) == 1) {
        unsigned long a = ntohl(v4.s_addr);
        return a && a != 0xffffffffUL && (a >> 24) != 127 && (a >> 28) != 14;
    }
    if (inet_pton(AF_INET6, s, &v6) == 1)
        return !IN6_IS_ADDR_UNSPECIFIED(&v6) && !IN6_IS_ADDR_LOOPBACK(&v6) &&
               !IN6_IS_ADDR_MULTICAST(&v6) && !IN6_IS_ADDR_V4MAPPED(&v6);
    return 0;
}
static int private_directory(const char *path, uid_t owner) {
    char resolved[PATH_MAX];
    struct stat info;
    if (!path || path[0] != '/' || !realpath(path, resolved) || strcmp(path, resolved)) return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &info) || !S_ISDIR(info.st_mode) || info.st_uid != owner ||
        (info.st_mode & 0777) != 0700) { close(fd); return -1; }
    return fd;
}
static int drop_privileges(uid_t uid, gid_t gid, const char *username) {
    if (initgroups(username, gid) || setgid(gid) || setuid(uid)) return 0;
    return getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid;
}
static int worker_alive(pid_t pid, uid_t uid) {
    if (kill(pid, 0) < 0 && errno != EPERM) return 0;
#ifdef __APPLE__
    struct proc_bsdinfo info;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return count == (int)sizeof(info) && info.pbi_uid == uid;
#else
    (void)uid;
    return 1;
#endif
}
static int child_has_uid(pid_t pid, uid_t uid) {
#ifdef __APPLE__
    struct proc_bsdinfo info;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return count == (int)sizeof(info) && info.pbi_uid == uid;
#else
    (void)pid; (void)uid;
    return 0; /* Non-macOS builds only support --self-test. */
#endif
}
static int log_confirms_interface(const char *log, const char *interface) {
    char prefix[128];
    int count = snprintf(prefix, sizeof(prefix), "listening on %s", interface);
    if (count < 0 || (size_t)count >= sizeof(prefix)) return 0;
    const char *found = strstr(log, prefix);
    if (!found) return 0;
    char boundary = found[count];
    return boundary == ',' || boundary == ' ' || boundary == '\n' || boundary == '\0';
}
static int regular_file(int dir, const char *name, uid_t owner, struct stat *info) {
    return fstatat(dir, name, info, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(info->st_mode) && info->st_uid == owner && (info->st_mode & 0777) == 0600;
}
static int stop_requested(int dir, uid_t owner) {
    struct stat info;
    return regular_file(dir, "stop", owner, &info);
}
static int heartbeat_fresh(int dir, uid_t owner, double *last_change, struct timespec *previous) {
    struct stat info;
    if (!regular_file(dir, "heartbeat", owner, &info)) return 0;
#ifdef __APPLE__
    struct timespec modified = info.st_mtimespec;
#else
    struct timespec modified = info.st_mtim;
#endif
    if (modified.tv_sec != previous->tv_sec || modified.tv_nsec != previous->tv_nsec) {
        *previous = modified;
        *last_change = monotonic_now();
    }
    return monotonic_now() - *last_change < HEARTBEAT_SECONDS;
}
static int write_all(int fd, const char *text, size_t size) {
    while (size) {
        ssize_t count = write(fd, text, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        text += count; size -= (size_t)count;
    }
    return 1;
}
static void capture_statistics(const char *log, long values[3]) {
    values[0] = values[1] = values[2] = -1;
    if (!log) return;
    for (const char *line = log; *line;) {
        const char *next = strchr(line, '\n');
        size_t length = next ? (size_t)(next - line) : strlen(line);
        if (length < 256) {
            char row[256]; memcpy(row, line, length); row[length] = 0;
            long count; char suffix[128] = {0};
            if (sscanf(row, "%ld %127[^\n]", &count, suffix) == 2 && count >= 0) {
                if (!strcmp(suffix, "packets captured") || !strcmp(suffix, "packet captured")) values[0] = count;
                if (!strcmp(suffix, "packets received by filter") || !strcmp(suffix, "packet received by filter")) values[1] = count;
                if (!strcmp(suffix, "packets dropped by kernel") || !strcmp(suffix, "packet dropped by kernel")) values[2] = count;
            }
        }
        if (!next) break;
        line = next + 1;
    }
}
static int status_json(int dir, const char *nonce, const char *state, pid_t child,
                       const char *reason, int process_exit, int graceful,
                       int still_running, int cleanup_review, const char *log) {
    /* All callers must have permanently dropped privileges. */
    if (geteuid() == 0) return 0;
    char numbers[3][32];
    long values[3]; capture_statistics(log, values);
    for (int i = 0; i < 3; ++i) {
        if (values[i] < 0) strcpy(numbers[i], "null");
        else snprintf(numbers[i], sizeof(numbers[i]), "%ld", values[i]);
    }
    char exit_value[32];
    if (process_exit == INT_MIN) strcpy(exit_value, "null");
    else snprintf(exit_value, sizeof(exit_value), "%d", process_exit);
    char payload[2048];
    int length = snprintf(payload, sizeof(payload),
        "{\"schema\":1,\"nonce\":\"%s\",\"state\":\"%s\",\"tcpdump_pid\":%ld,"
        "\"reason\":\"%s\",\"process_exit\":%s,\"graceful\":%s,"
        "\"still_running\":%s,\"cleanup_requires_review\":%s,"
        "\"stats\":{\"captured\":%s,\"received_by_filter\":%s,\"dropped_by_kernel\":%s}}\n",
        nonce, state, (long)child, reason, exit_value, graceful ? "true" : "false",
        still_running ? "true" : "false", cleanup_review ? "true" : "false",
        numbers[0], numbers[1], numbers[2]);
    if (length < 0 || (size_t)length >= sizeof(payload)) return 0;
    unlinkat(dir, "status.tmp", 0);
    int fd = openat(dir, "status.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    int okay = write_all(fd, payload, (size_t)length) && fsync(fd) == 0;
    close(fd);
    if (okay) okay = renameat(dir, "status.tmp", dir, "status.json") == 0;
    return okay;
}
static int append_log(int fd, char *buffer, size_t *used, const char *data, size_t size) {
    if (fd >= 0 && !write_all(fd, data, size)) return 0;
    size_t room = LOG_CAPACITY - 1 - *used;
    if (size > room) size = room;
    memcpy(buffer + *used, data, size); *used += size; buffer[*used] = 0;
    return 1;
}
static int exit_code(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return INT_MIN;
}
static int self_test(void) {
    unsigned long number;
    long statistics[3];
    capture_statistics("17 packets captured\n19 packets received by filter\n2 packets dropped by kernel\n", statistics);
    int okay = valid_ip("192.0.2.20") && valid_ip("2001:db8::42") &&
        !valid_ip("127.0.0.1") && !valid_ip("224.0.0.1") &&
        !valid_ip("host.invalid") && !valid_ip("192.0.2.20;id") &&
        valid_interface("rvi12") && !valid_interface("en0") &&
        !valid_interface("rvi1;id") && valid_nonce("0123456789abcdef0123456789abcdef") &&
        !valid_nonce("../status") && decimal("501", &number) && !decimal("-1", &number) &&
        statistics[0] == 17 && statistics[1] == 19 && statistics[2] == 2 &&
        log_confirms_interface("tcpdump: listening on rvi7, link-type", "rvi7") &&
        !log_confirms_interface("tcpdump: listening on rvi70, link-type", "rvi7");
    puts(okay ? "{\"self_test\":\"passed\",\"capture_attempted\":false}" : "{\"self_test\":\"failed\"}");
    return okay ? 0 : 1;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc != 11 || strcmp(argv[1], "--capture") != 0) {
        fputs("Expected --capture UID GID USERNAME RVI IP SESSION_DIRECTORY WORKER_PID NONCE EXPECTED_IFINDEX\n", stderr); return 64;
    }
    unsigned long raw_uid, raw_gid, raw_pid, expected_ifindex;
    if (!decimal(argv[2], &raw_uid) || !raw_uid || !decimal(argv[3], &raw_gid) ||
        !decimal(argv[8], &raw_pid) || raw_pid < 2 || !valid_interface(argv[5]) ||
        !valid_ip(argv[6]) || !valid_nonce(argv[9]) || !decimal(argv[10], &expected_ifindex) || !expected_ifindex) return 64;
    uid_t uid = (uid_t)raw_uid; gid_t gid = (gid_t)raw_gid; pid_t worker = (pid_t)raw_pid;
    struct passwd *user = getpwuid(uid);
    if (!user || strcmp(user->pw_name, argv[4]) || user->pw_gid != gid) return 64;
    if (geteuid() != 0) { fputs("System administrator authorization is required.\n", stderr); return 77; }
#ifndef __APPLE__
    fputs("Capture is supported only on macOS.\n", stderr); return 78;
#endif
    umask(077);
    int session = private_directory(argv[7], uid);
    if (session < 0) return 64;
    char control_path[PATH_MAX], output_path[PATH_MAX];
    if (snprintf(control_path, sizeof(control_path), "%s/.gui-capture-%s", argv[7], argv[9]) >= (int)sizeof(control_path) ||
        snprintf(output_path, sizeof(output_path), "%s/traffic.pcap", argv[7]) >= (int)sizeof(output_path)) { close(session); return 64; }
    int control = private_directory(control_path, uid);
    if (control < 0) { close(session); return 64; }
    if (if_nametoindex(argv[5]) != expected_ifindex) {
        if (!drop_privileges(uid, gid, argv[4])) return 77;
        status_json(control, argv[9], "finished", 0, "interface_generation_changed", INT_MIN, 0, 0, 1, NULL);
        close(control); close(session); return 0;
    }
    struct timespec previous_heartbeat = {0, 0};
    double last_heartbeat = monotonic_now();
    int initially_alive = worker_alive(worker, uid);
    int initially_fresh = heartbeat_fresh(control, uid, &last_heartbeat, &previous_heartbeat);
    if (stop_requested(control, uid) || !initially_alive || !initially_fresh) {
        if (!drop_privileges(uid, gid, argv[4])) return 77;
        const char *reason = !initially_alive ? "worker_disappeared" : (!initially_fresh ? "heartbeat_timeout" : "cancelled_before_start");
        status_json(control, argv[9], "finished", 0, reason, 0, 1, 0, !initially_alive || !initially_fresh, NULL);
        close(control); close(session); return 0;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action)); action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL); sigaction(SIGHUP, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    int pipes[2];
    if (pipe(pipes)) { close(control); close(session); return 71; }
    fcntl(pipes[0], F_SETFD, FD_CLOEXEC); fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
    pid_t child = fork();
    if (child == 0) {
        signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGHUP, SIG_DFL);
        int null = open("/dev/null", O_RDWR);
        if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0) _exit(71);
        if (null > STDERR_FILENO) close(null);
        close(pipes[0]); close(pipes[1]); close(control); close(session);
        char filter[160];
        if (snprintf(filter, sizeof(filter), "host %s and (tcp or udp)", argv[6]) >= (int)sizeof(filter)) _exit(64);
        char *command[] = {"/usr/sbin/tcpdump", "-i", argv[5], "-n", "-p", "-s", "0", "-U", "-Z", argv[4], "-w", output_path, filter, NULL};
        char *environment[] = {"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
        execve(command[0], command, environment); _exit(71);
    }
    close(pipes[1]);
    if (child < 0) { close(pipes[0]); close(control); close(session); return 71; }
    fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_NONBLOCK);
    char log[LOG_CAPACITY]; size_t used = 0; log[0] = 0;
    int logfd = -1, finished = 0, status = 0, dropped_privileges = 0;
    int ready = 0, stopping = 0, escalated = 0, failure = 0, exit_unknown = 0;
    const char *reason = "completed";
    double started = monotonic_now(), stop_started = 0;
    for (;;) {
        char chunk[4096]; ssize_t count;
        while ((count = read(pipes[0], chunk, sizeof(chunk))) > 0) {
            if (!append_log(logfd, log, &used, chunk, (size_t)count)) { failure = 1; reason = "log_write_failed"; }
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) { finished = 1; break; }
        if (waited < 0 && errno == ECHILD) { finished = 1; exit_unknown = 1; failure = 1; reason = "child_status_unknown"; break; }
        double current = monotonic_now();
        if (if_nametoindex(argv[5]) != expected_ifindex) { failure = 1; reason = "interface_generation_changed"; }
        if (!ready && !dropped_privileges && !failure && log_confirms_interface(log, argv[5]) && child_has_uid(child, uid)) {
            if (!drop_privileges(uid, gid, argv[4])) { failure = 1; reason = "privilege_drop_failed"; }
            else {
                dropped_privileges = 1;
                logfd = openat(session, "tcpdump.log", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (logfd < 0 || !write_all(logfd, log, used)) { failure = 1; reason = "log_write_failed"; }
                else if (!status_json(control, argv[9], "capturing", child, "ready", INT_MIN, 1, 1, 0, NULL)) { failure = 1; reason = "status_write_failed"; }
                else ready = 1;
            }
        }
        int alive = worker_alive(worker, uid);
        int heartbeat = heartbeat_fresh(control, uid, &last_heartbeat, &previous_heartbeat);
        if (!stopping && (interrupted || stop_requested(control, uid) || !alive || !heartbeat || failure ||
                         (!ready && current - started >= STARTUP_SECONDS) || current - started >= CAPTURE_SECONDS)) {
            if (!alive) reason = "worker_disappeared";
            else if (!heartbeat) reason = "heartbeat_timeout";
            else if (interrupted) reason = "helper_interrupted";
            else if (stop_requested(control, uid)) reason = "user_stop";
            else if (!ready && !failure) reason = "startup_timeout";
            else if (!failure) reason = "capture_time_limit";
            kill(child, SIGINT); stopping = 1; stop_started = current;
        }
        if (stopping && current - stop_started >= 8 && escalated < 1) { kill(child, SIGTERM); escalated = 1; }
        if (stopping && current - stop_started >= 12 && escalated < 2) { kill(child, SIGKILL); escalated = 2; }
        if (stopping && current - stop_started >= 16) { reason = "child_exit_unconfirmed"; break; }
        struct pollfd pfd = {pipes[0], POLLIN, 0}; poll(&pfd, 1, 100);
    }
    /* A child may exit before dropping privileges. Retain root only until its
     * own process has been reaped, then drop before any filesystem writes. */
    if (!dropped_privileges) {
        if (!drop_privileges(uid, gid, argv[4])) { close(pipes[0]); close(control); close(session); return 77; }
        dropped_privileges = 1;
        logfd = openat(session, "tcpdump.log", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (logfd < 0 || !write_all(logfd, log, used)) failure = 1;
    }
    char tail[4096]; ssize_t count;
    while ((count = read(pipes[0], tail, sizeof(tail))) > 0)
        if (!append_log(logfd, log, &used, tail, (size_t)count)) failure = 1;
    close(pipes[0]);
    if (logfd >= 0) { if (fsync(logfd)) failure = 1; close(logfd); }
    int review = !worker_alive(worker, uid) || strcmp(reason, "heartbeat_timeout") == 0 || !finished;
    int code = finished && !exit_unknown ? exit_code(status) : INT_MIN;
    if (!ready && strcmp(reason, "completed") == 0) reason = "startup_failed";
    int okay = status_json(control, argv[9], "finished", child, reason, code,
                           finished && !escalated && !failure, !finished, review, log);
    close(control); close(session);
    return finished && okay && !failure ? 0 : 1;
}
