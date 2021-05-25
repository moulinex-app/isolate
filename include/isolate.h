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


void run(char **argv, isolate_config config);

void init(isolate_config config);

void cleanup(isolate_config config);
