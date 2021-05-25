/*
 *	A Process Isolator based on Linux Containers
 *
 *	(c) 2012-2020 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* May not be defined in older glibc headers */
#ifndef MS_PRIVATE
#    warning "Working around old glibc: no MS_PRIVATE"
#    define MS_PRIVATE (1 << 18)
#endif
#ifndef MS_REC
#    warning "Working around old glibc: no MS_REC"
#    define MS_REC (1 << 14)
#endif

typedef struct isolate_config
{
    char **argv;
    // When multiple sandboxes are used in parallel, each must get a unique ID
    int box_id;
    // Change directory to <set_cwd> before executing the program
    char *set_cwd;
    // Enable use of control groups
    int cg_enable;
    // Do not add default directory rules
    int default_dirs;
    // Inherit full environment of the parent process
    int pass_environ;
    // Max size (in KB) of files that can be created
    int fsize_limit;
    // Limit stack size to <stack_limit> KB (default: 0=unlimited)
    int stack_limit;
    // Redirect stdin to <redir_strin>
    char *redir_stdin;
    // Redirect stdin to <redir_strout>
    char *redir_stdout;
    // Limit address space to <memory_limit> KB
    int memory_limit;
    // Output process information to <meta>
    char *meta;
    // Enable multiple processes (at most <max> of them); needs --cg
    int max_processes;
    // Set disk quota to <blk> blocks and <ino> inodes
    int blk;
    int ino;
    // Redirect stderr to <redir_stderr>
    char *redir_stderr;
    // Redirect stderr to stdout
    int redir_stderr_stdout;
    // Do not print status messages except for fatal errors
    int silent;
    // Set run time limit (seconds, fractions allowed)
    int timeout;
    // Be verbose (use multiple times for even more verbosity)
    int verbose;
    // Set wall clock time limit (seconds, fractions allowed)
    int wall_timeout;
    // Set extra timeout, before which a timing-out program is not yet killed
    // so that its real execution time is reported (seconds, fractions allowed)
    int extra_timeout;
    // Limit memory usage of the control group to <size> KB
    int cg_memory_limit;
    // Time limits affects total run time of the control
    int cg_timing;
    // Share network namespace with the parent process
    int share_net;
    // Inherit all file descriptors of the parent process
    int inherit_fds;
} isolate_config;

int setup(isolate_config config);

/*
 * Theory of operation
 *
 * Generally, we want to run a process inside a namespace/cgroup and watch it
 * from the outside. However, the reality is a little bit more complicated as we
 * do not want the inside process to become the init process of the PID
 * namespace (we want to have all signals properly delivered).
 *
 * We are running three processes:
 *
 *   - Keeper process (root privileges, parent namespace, parent cgroups)
 *   - Proxy process (UID/GID of the calling user, init process of the child
 *     namespace, parent cgroups)
 *   - Inside process (per-box UID/GID, child namespace, child cgroups)
 *
 * The proxy process just waits for the inside process to exit and then it
 * passes the exit status to the keeper.
 *
 * We use two pipes:
 *
 *   - Error pipe for error messages produced by the proxy process and the early
 *     stages of the inside process (until exec()). Listened to by the keeper.
 *   - Status pipe for passing the PID of the inside process and its exit status
 *     from the proxy to the keeper.
 */

#define TIMER_INTERVAL_US 100000

static int already_configured = 0;
static int timeout; /* milliseconds */
static int wall_timeout;
static int extra_timeout;
int pass_environ;
int verbose;
static int silent;
static int fsize_limit;
static int memory_limit;
static int stack_limit;
int block_quota;
int inode_quota;
static int max_processes = 1;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static int redir_stderr_to_stdout;
static char *set_cwd;
static int share_net;
static int inherit_fds;
static int default_dirs = 1;
static int tty_hack;

int cg_enable;
int cg_memory_limit;
int cg_timing = 1;

int box_id;
static char box_dir[1024];
static pid_t box_pid;
static pid_t proxy_pid;

uid_t box_uid;
gid_t box_gid;
uid_t orig_uid;
gid_t orig_gid;

static int partial_line;
static int cleanup_ownership;

static struct timeval start_time;
static int ticks_per_sec;
static int total_ms, wall_ms;
static volatile sig_atomic_t timer_tick, interrupt;

static int error_pipes[2];
static int write_errors_to_fd;
static int read_errors_from_fd;

static int status_pipes[2];

static int get_wall_time_ms(void);
static int get_run_time_ms(struct rusage *rus);

/*** Messages and exits ***/

static void final_stats(struct rusage *rus)
{
    total_ms = get_run_time_ms(rus);
    wall_ms = get_wall_time_ms();

    meta_printf("time:%d.%03d\n", total_ms / 1000, total_ms % 1000);
    meta_printf("time-wall:%d.%03d\n", wall_ms / 1000, wall_ms % 1000);
    meta_printf("max-rss:%ld\n", rus->ru_maxrss);
    meta_printf("csw-voluntary:%ld\n", rus->ru_nvcsw);
    meta_printf("csw-forced:%ld\n", rus->ru_nivcsw);

    cg_stats();
}

static void NONRET box_exit(int rc)
{
    if (proxy_pid > 0)
    {
        if (box_pid > 0)
        {
            kill(-box_pid, SIGKILL);
            kill(box_pid, SIGKILL);
        }
        if (cg_enable)
        {
            /*
             *  In non-CG mode, we must not kill the proxy explicitly.
             *  This is important, because the proxy could exit before the box
             *  completes its exit, causing rusage of the box to be lost.
             *
             *  In CG mode, we must kill the proxy, because it is the init
             *  process of the CG and killing it causes all other processes
             *  inside the CG to be killed. However, we do not care about
             *  rusage (unless somebody asks for --no-cg-timing, which is not
             *  reliable anyway).
             */
            kill(-proxy_pid, SIGKILL);
            kill(proxy_pid, SIGKILL);
        }
        meta_printf("killed:1\n");

        /*
         *  The rusage will contain time spent by the proxy and its children
         * (i.e., the box). (See comments on killing of the proxy above,
         * though.)
         */
        struct rusage rus;
        int p, stat;
        do
            p = wait4(proxy_pid, &stat, 0, &rus);
        while (p < 0 && errno == EINTR);
        if (p < 0)
            fprintf(stderr, "UGH: Lost track of the process (%m)\n");
        else
            final_stats(&rus);
    }

    if (tty_hack && isatty(1))
    {
        /*
         *  If stdout is a tty, make us the foreground process group again.
         *  We do not need it (we ignore SIGTTOU anyway), but programs executed
         *  after our exit will.
         */
        tcsetpgrp(1, getpgrp());
    }

    if (rc < 2 && cleanup_ownership)
        chowntree("box", orig_uid, orig_gid);

    meta_close();
    exit(rc);
}

static void flush_line(void)
{
    if (partial_line)
        fputc('\n', stderr);
    partial_line = 0;
}

/* Report an error of the sandbox itself */
void NONRET __attribute__((format(printf, 1, 2))) die(char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), msg, args);

    // If the child processes are still running, show no mercy.
    if (box_pid > 0)
    {
        kill(-box_pid, SIGKILL);
        kill(box_pid, SIGKILL);
    }
    if (proxy_pid > 0)
    {
        kill(-proxy_pid, SIGKILL);
        kill(proxy_pid, SIGKILL);
    }

    if (write_errors_to_fd)
    {
        // We are inside the box, have to use error pipe for error reporting.
        // We hope that the whole error message fits in PIPE_BUF bytes.
        write(write_errors_to_fd, buf, n);
        exit(2);
    }

    // Otherwise, we in the box keeper process, so we report errors normally
    flush_line();
    meta_printf("status:XX\nmessage:%s\n", buf);
    fputs(buf, stderr);
    fputc('\n', stderr);
    box_exit(2);
}

/* Report an error of the program inside the sandbox */
void NONRET __attribute__((format(printf, 1, 2))) err(char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    flush_line();
    if (msg[0] && msg[1] && msg[2] == ':' && msg[3] == ' ')
    {
        meta_printf("status:%c%c\n", msg[0], msg[1]);
        msg += 4;
    }
    char buf[1024];
    vsnprintf(buf, sizeof(buf), msg, args);
    meta_printf("message:%s\n", buf);
    if (!silent)
    {
        fputs(buf, stderr);
        fputc('\n', stderr);
    }
    box_exit(1);
}

/* Write a message, but only if in verbose mode */
void __attribute__((format(printf, 1, 2))) msg(char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    if (verbose)
    {
        int len = strlen(msg);
        if (len > 0)
            partial_line = (msg[len - 1] != '\n');
        vfprintf(stderr, msg, args);
        fflush(stderr);
    }
    va_end(args);
}

/*** Signal handling in keeper process ***/

/*
 *   Signal handling is tricky. We must set up signal handlers before
 *   we start the child process (and reset them in the child process).
 *   Otherwise, there is a short time window where a SIGINT can kill
 *   us and leave the child process running.
 */

struct signal_rule
{
    int signum;
    enum
    {
        SIGNAL_IGNORE,
        SIGNAL_INTERRUPT,
        SIGNAL_FATAL
    } action;
};

static const struct signal_rule signal_rules[] = {
    { SIGHUP, SIGNAL_INTERRUPT },  { SIGINT, SIGNAL_INTERRUPT },
    { SIGQUIT, SIGNAL_INTERRUPT }, { SIGILL, SIGNAL_FATAL },
    { SIGABRT, SIGNAL_FATAL },     { SIGFPE, SIGNAL_FATAL },
    { SIGSEGV, SIGNAL_FATAL },     { SIGPIPE, SIGNAL_IGNORE },
    { SIGTERM, SIGNAL_INTERRUPT }, { SIGUSR1, SIGNAL_IGNORE },
    { SIGUSR2, SIGNAL_IGNORE },    { SIGBUS, SIGNAL_FATAL },
    { SIGTTOU, SIGNAL_IGNORE },
};

static void signal_alarm(int unused UNUSED)
{
    /* Time limit checks are synchronous, so we only schedule them there. */
    timer_tick = 1;
    msg("[timer]");
}

static void signal_int(int signum)
{
    /* Interrupts (e.g., SIGINT) are synchronous, too. */
    interrupt = signum;
}

static void signal_fatal(int signum)
{
    /* If we receive SIGSEGV or a similar signal, we try to die gracefully. */
    die("Sandbox keeper received fatal signal %d", signum);
}

static void setup_signals(void)
{
    struct sigaction sa_int, sa_fatal;
    bzero(&sa_int, sizeof(sa_int));
    sa_int.sa_handler = signal_int;
    bzero(&sa_fatal, sizeof(sa_fatal));
    sa_fatal.sa_handler = signal_fatal;

    for (int i = 0; i < ARRAY_SIZE(signal_rules); i++)
    {
        const struct signal_rule *sr = &signal_rules[i];
        switch (sr->action)
        {
        case SIGNAL_IGNORE:
            signal(sr->signum, SIG_IGN);
            break;
        case SIGNAL_INTERRUPT:
            sigaction(sr->signum, &sa_int, NULL);
            break;
        case SIGNAL_FATAL:
            sigaction(sr->signum, &sa_fatal, NULL);
            break;
        default:
            die("Invalid signal rule");
        }
    }
}

static void reset_signals(void)
{
    for (int i = 0; i < ARRAY_SIZE(signal_rules); i++)
        signal(signal_rules[i].signum, SIG_DFL);
}

/*** The keeper process ***/

#define PROC_BUF_SIZE 4096
static int read_proc_file(char *buf, char *name, int *fdp)
{
    int c;

    if (*fdp < 0)
    {
        snprintf(buf, PROC_BUF_SIZE, "/proc/%d/%s", (int)box_pid, name);
        *fdp = open(buf, O_RDONLY);
        if (*fdp < 0)
            return 0; // This is OK, the process could have finished
    }
    lseek(*fdp, 0, SEEK_SET);
    if ((c = read(*fdp, buf, PROC_BUF_SIZE - 1)) < 0)
    {
        // Even this could fail if the process disappeared since open()
        return 0;
    }
    if (c >= PROC_BUF_SIZE - 1)
        die("/proc/$pid/%s too long", name);
    buf[c] = 0;
    return 1;
}

static int get_wall_time_ms(void)
{
    struct timeval now, wall;
    gettimeofday(&now, NULL);
    timersub(&now, &start_time, &wall);
    return wall.tv_sec * 1000 + wall.tv_usec / 1000;
}

static int get_run_time_ms(struct rusage *rus)
{
    if (cg_enable && cg_timing)
        return cg_get_run_time_ms();

    if (rus)
    {
        struct timeval total;
        timeradd(&rus->ru_utime, &rus->ru_stime, &total);
        return total.tv_sec * 1000 + total.tv_usec / 1000;
    }

    // It might happen that we do not know the box_pid (see comments in
    // find_box_pid())
    if (!box_pid)
        return 0;

    char buf[PROC_BUF_SIZE], *x;
    int utime, stime;
    static int proc_stat_fd = -1;

    if (!read_proc_file(buf, "stat", &proc_stat_fd))
        return 0;
    x = buf;
    while (*x && *x != ' ')
        x++;
    while (*x == ' ')
        x++;
    if (*x++ != '(')
        die("proc stat syntax error 1");
    while (*x && (*x != ')' || x[1] != ' '))
        x++;
    while (*x == ')' || *x == ' ')
        x++;
    if (sscanf(x, "%*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d %d", &utime,
               &stime)
        != 2)
        die("proc stat syntax error 2");

    return (utime + stime) * 1000 / ticks_per_sec;
}

static void check_timeout(void)
{
    if (wall_timeout)
    {
        int wall_ms = get_wall_time_ms();
        if (wall_ms > wall_timeout)
            err("TO: Time limit exceeded (wall clock)");
        if (verbose > 1)
            fprintf(stderr, "[wall time check: %d msec]\n", wall_ms);
    }
    if (timeout)
    {
        int ms = get_run_time_ms(NULL);
        if (verbose > 1)
            fprintf(stderr, "[time check: %d msec]\n", ms);
        if (ms > timeout && ms > extra_timeout)
            err("TO: Time limit exceeded");
    }
}

static void box_keeper(void)
{
    read_errors_from_fd = error_pipes[0];
    close(error_pipes[1]);
    close(status_pipes[1]);

    gettimeofday(&start_time, NULL);
    ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0)
        die("Invalid ticks_per_sec!");

    if (timeout || wall_timeout)
    {
        struct sigaction sa;
        bzero(&sa, sizeof(sa));
        sa.sa_handler = signal_alarm;
        sigaction(SIGALRM, &sa, NULL);
        struct itimerval timer = {
            .it_interval = { .tv_usec = TIMER_INTERVAL_US },
            .it_value = { .tv_usec = TIMER_INTERVAL_US },
        };
        setitimer(ITIMER_REAL, &timer, NULL);
    }

    for (;;)
    {
        struct rusage rus;
        int stat;
        pid_t p;
        if (interrupt)
        {
            meta_printf("exitsig:%d\n", interrupt);
            err("SG: Interrupted");
        }
        if (timer_tick)
        {
            check_timeout();
            timer_tick = 0;
        }
        p = wait4(proxy_pid, &stat, 0, &rus);
        if (p < 0)
        {
            if (errno == EINTR)
                continue;
            die("wait4: %m");
        }
        if (p != proxy_pid)
            die("wait4: unknown pid %d exited!", p);
        proxy_pid = 0;

        // Check error pipe if there is an internal error passed from inside the
        // box
        char interr[1024];
        int n = read(read_errors_from_fd, interr, sizeof(interr) - 1);
        if (n > 0)
        {
            interr[n] = 0;
            die("%s", interr);
        }

        // Check status pipe if there is an exit status reported by the proxy
        // process
        n = read(status_pipes[0], &stat, sizeof(stat));
        if (n != sizeof(stat))
            die("Did not receive exit status from proxy");

        // At this point, the rusage includes time spent by the proxy's
        // children.
        final_stats(&rus);
        if (timeout && total_ms > timeout)
            err("TO: Time limit exceeded");
        if (wall_timeout && wall_ms > wall_timeout)
            err("TO: Time limit exceeded (wall clock)");

        if (WIFEXITED(stat))
        {
            meta_printf("exitcode:%d\n", WEXITSTATUS(stat));
            if (WEXITSTATUS(stat))
                err("RE: Exited with error status %d", WEXITSTATUS(stat));
            flush_line();
            if (!silent)
            {
                fprintf(stderr, "OK (%d.%03d sec real, %d.%03d sec wall)\n",
                        total_ms / 1000, total_ms % 1000, wall_ms / 1000,
                        wall_ms % 1000);
            }
            return;
        }
        else if (WIFSIGNALED(stat))
        {
            meta_printf("exitsig:%d\n", WTERMSIG(stat));
            err("SG: Caught fatal signal %d", WTERMSIG(stat));
        }
        else if (WIFSTOPPED(stat))
        {
            meta_printf("exitsig:%d\n", WSTOPSIG(stat));
            err("SG: Stopped by signal %d", WSTOPSIG(stat));
        }
        else
            die("wait4: unknown status %x, giving up!", stat);
    }
}

/*** The process running inside the box ***/

static void setup_root(void)
{
    if (mkdir("root", 0750) < 0 && errno != EEXIST)
        die("mkdir('root'): %m");

    /*
     * Ensure all mounts are private, not shared. We don't want our mounts
     * appearing outside of our namespace.
     * (systemd since version 188 mounts filesystems shared by default).
     */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        die("Cannot privatize mounts: %m");

    if (mount("none", "root", "tmpfs", 0, "mode=755") < 0)
        die("Cannot mount root ramdisk: %m");

    apply_dir_rules(default_dirs);

    if (chroot("root") < 0)
        die("Chroot failed: %m");

    if (chdir("root/box") < 0)
        die("Cannot change current directory: %m");
}

static void setup_credentials(void)
{
    if (setresgid(box_gid, box_gid, box_gid) < 0)
        die("setresgid: %m");
    if (setgroups(0, NULL) < 0)
        die("setgroups: %m");
    if (setresuid(box_uid, box_uid, box_uid) < 0)
        die("setresuid: %m");
    setpgrp();
    if (tty_hack && isatty(1))
    {
        // If stdout is a tty, make us the foreground process group
        signal(SIGTTOU, SIG_IGN);
        tcsetpgrp(1, getpgrp());
        signal(SIGTTOU, SIG_DFL);
    }
}

static void setup_fds(void)
{
    if (redir_stdin)
    {
        close(0);
        if (open(redir_stdin, O_RDONLY) != 0)
            die("open(\"%s\"): %m", redir_stdin);
    }
    if (redir_stdout)
    {
        close(1);
        if (open(redir_stdout, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1)
            die("open(\"%s\"): %m", redir_stdout);
    }
    if (redir_stderr)
    {
        close(2);
        if (open(redir_stderr, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 2)
            die("open(\"%s\"): %m", redir_stderr);
    }
    if (redir_stderr_to_stdout)
    {
        if (dup2(1, 2) < 0)
            die("Cannot dup stdout to stderr: %m");
    }
}

static void setup_rlim(const char *res_name, int res, rlim_t limit)
{
    struct rlimit rl = { .rlim_cur = limit, .rlim_max = limit };
    if (setrlimit(res, &rl) < 0)
        die("setrlimit(%s, %jd)", res_name, (intmax_t)limit);
}

static void setup_rlimits(void)
{
#define RLIM(res, val) setup_rlim("RLIMIT_" #res, RLIMIT_##res, val)

    if (memory_limit)
        RLIM(AS, (rlim_t)memory_limit * 1024);

    if (fsize_limit)
        RLIM(FSIZE, (rlim_t)fsize_limit * 1024);

    RLIM(STACK, (stack_limit ? (rlim_t)stack_limit * 1024 : RLIM_INFINITY));
    RLIM(NOFILE, 64);
    RLIM(MEMLOCK, 0);

    if (max_processes)
        RLIM(NPROC, max_processes);

#undef RLIM
}

static int box_inside(char **args)
{
    cg_enter();
    setup_root();
    setup_rlimits();
    setup_credentials();
    setup_fds();
    char **env = setup_environment();

    if (set_cwd && chdir(set_cwd))
        die("chdir: %m");

    execve(args[0], args, env);
    err("execve(\"%s\"): %m", args[0]);
}

/*** Proxy ***/

static void setup_orig_credentials(void)
{
    if (setresgid(orig_gid, orig_gid, orig_gid) < 0)
        die("setresgid: %m");
    if (setgroups(0, NULL) < 0)
        die("setgroups: %m");
    if (setresuid(orig_uid, orig_uid, orig_uid) < 0)
        die("setresuid: %m");
}

static int box_proxy(void *arg)
{
    char **args = arg;

    write_errors_to_fd = error_pipes[1];
    close(error_pipes[0]);
    close(status_pipes[0]);
    meta_close();
    reset_signals();

    pid_t inside_pid = fork();
    if (inside_pid < 0)
        die("Cannot run process, fork failed: %m");
    else if (!inside_pid)
    {
        close(status_pipes[1]);
        box_inside(args);
        _exit(42); // We should never get here
    }

    setup_orig_credentials();
    if (write(status_pipes[1], &inside_pid, sizeof(inside_pid))
        != sizeof(inside_pid))
        die("Proxy write to pipe failed: %m");

    int stat;
    pid_t p = waitpid(inside_pid, &stat, 0);
    if (p < 0)
        die("Proxy waitpid() failed: %m");

    if (write(status_pipes[1], &stat, sizeof(stat)) != sizeof(stat))
        die("Proxy write to pipe failed: %m");

    _exit(0);
}

static void box_init(void)
{
    if (box_id < 0 || box_id >= cf_num_boxes)
        die("Sandbox ID out of range (allowed: 0-%d)", cf_num_boxes - 1);
    box_uid = cf_first_uid + box_id;
    box_gid = cf_first_gid + box_id;

    snprintf(box_dir, sizeof(box_dir), "%s/%d", cf_box_root, box_id);
    make_dir(box_dir);
    if (chdir(box_dir) < 0)
        die("chdir(%s): %m", box_dir);
}

/*** Commands ***/

static const char *self_name(void)
{
    return cg_enable ? "isolate --cg" : "isolate";
}

void init(isolate_config config)
{
    if(!already_configured)
        setup(config);
    msg("Preparing sandbox directory\n");
    if (mkdir("box", 0700) < 0)
    {
        if (errno == EEXIST)
            die("Box already exists, run `%s --cleanup' first", self_name());
        else
            die("Cannot create box: %m");
    }
    if (chown("box", orig_uid, orig_gid) < 0)
        die("Cannot chown box: %m");

    cg_prepare();
    set_quota();

    puts(box_dir);
}

void cleanup(isolate_config config)
{
    if(!already_configured)
        setup(config);
    if (!dir_exists("box"))
    {
        msg("Nothing to do -- box directory did not exist\n");
        return;
    }

    msg("Deleting sandbox directory\n");
    rmtree(box_dir);
    cg_remove();
}

static void setup_pipe(int *fds, int nonblocking)
{
    if (pipe(fds) < 0)
        die("pipe: %m");
    for (int i = 0; i < 2; i++)
        if (fcntl(fds[i], F_SETFD, fcntl(fds[i], F_GETFD) | FD_CLOEXEC) < 0
            || nonblocking
                && fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL) | O_NONBLOCK)
                    < 0)
            die("fcntl on pipe: %m");
}

static void find_box_pid(void)
{
    /*
     *  The box keeper process wants to poll status of the inside process,
     *  so it needs to know the box_pid. However, it is not easy to obtain:
     *  we got the PID from the proxy, but it is local to the PID namespace.
     *  Instead, we ask /proc to enumerate the children of the proxy.
     *
     *  CAVEAT: The timing is tricky. We know that the inside process was
     *  already started (passing the PID from the proxy to us guarantees it),
     *  but it might already have exited and be reaped by the proxy. Therefore
     *  it is correct if we fail to find anything.
     */

    char namebuf[256];
    snprintf(namebuf, sizeof(namebuf), "/proc/%d/task/%d/children",
             (int)proxy_pid, (int)proxy_pid);
    FILE *f = fopen(namebuf, "r");
    if (!f)
        return;

    int child;
    if (fscanf(f, "%d", &child) != 1)
    {
        fclose(f);
        return;
    }
    box_pid = child;

    if (fscanf(f, "%d", &child) == 1)
        die("Error parsing %s: unexpected children found", namebuf);

    fclose(f);
}

void run(char **argv, isolate_config config)
{
    if(!already_configured)
        setup(config);
    if (!dir_exists("box"))
        die("Box directory not found, did you run `%s --init'?", self_name());

    if (!inherit_fds)
        close_all_fds();

    chowntree("box", box_uid, box_gid);
    cleanup_ownership = 1;

    setup_pipe(error_pipes, 1);
    setup_pipe(status_pipes, 0);
    setup_signals();

    proxy_pid =
        clone(box_proxy, // Function to execute as the body of the new process
              (void *)((uintptr_t)argv
                       & ~(uintptr_t)15), // Pass our stack, aligned to 16-bytes
              SIGCHLD | CLONE_NEWIPC | (share_net ? 0 : CLONE_NEWNET)
                  | CLONE_NEWNS | CLONE_NEWPID,
              argv); // Pass the arguments
    if (proxy_pid < 0)
        die("Cannot run proxy, clone failed: %m");
    if (!proxy_pid)
        die("Cannot run proxy, clone returned 0");

    pid_t box_pid_inside_ns;
    int n =
        read(status_pipes[0], &box_pid_inside_ns, sizeof(box_pid_inside_ns));
    if (n != sizeof(box_pid_inside_ns))
        die("Proxy failed before it passed box_pid: %m");
    find_box_pid();
    msg("Started proxy_pid=%d box_pid=%d box_pid_inside_ns=%d\n",
        (int)proxy_pid, (int)box_pid, (int)box_pid_inside_ns);

    box_keeper();
}

int setup(isolate_config config)
{
    int c;
    int require_cg = 0;
    char *sep;

    init_dir_rules();

    if (config.box_id)
        box_id = config.box_id;
    if (config.set_cwd)
        set_cwd = config.set_cwd;
    if (config.cg_enable)
        cg_enable = config.cg_enable;
    if (config.default_dirs)
        default_dirs = config.default_dirs;
    // TODO Configure the directories options
    if (config.pass_environ)
        pass_environ = config.pass_environ;
    if (config.fsize_limit)
        fsize_limit = config.fsize_limit;
    // TODO Patch environnement variables with
    //! set_env_action(optarg)
    if (config.stack_limit)
        stack_limit = config.stack_limit;
    if (config.redir_stdin)
        redir_stdin = config.redir_stdin;
    if (config.memory_limit)
        memory_limit = config.memory_limit;
    if (config.meta)
        meta_open(config.meta);
    if (config.redir_stdout)
        redir_stdout = config.redir_stdout;
    if (config.max_processes)
        max_processes = config.max_processes;
    if (config.blk)
        block_quota = config.blk;
    if (config.ino)
        inode_quota = config.ino;
    if (config.redir_stderr)
        redir_stderr = config.redir_stderr;
    redir_stderr_to_stdout = config.redir_stderr_stdout;
    silent = config.silent;
    timeout = 1000 * config.timeout;
    verbose = config.verbose;
    wall_timeout = 1000 * config.wall_timeout;
    extra_timeout = 1000 * config.extra_timeout;
    cg_memory_limit = config.cg_memory_limit;
    cg_timing = config.cg_timing;
    if (cg_memory_limit || require_cg || cg_timing)
        require_cg = 1;
    share_net = config.share_net;
    inherit_fds = config.inherit_fds;

    if (geteuid())
        die("Must be started as root");
    if (getegid() && setegid(0) < 0)
        die("Cannot switch to root group: %m");

    orig_uid = getuid();
    orig_gid = getgid();

    umask(022);
    cf_parse();
    box_init();
    cg_init();
    already_configured = 1;
}
