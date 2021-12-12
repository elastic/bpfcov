#define _GNU_SOURCE

#ifdef NDEBUG
#define DEBUG 0
#else
#define DEBUG 1
#endif

/* C standard library */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/vfs.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <bpf/bpf.h>

#include <argp.h>

// --------------------------------------------------------------------------------------------------------------------
// Global info
// --------------------------------------------------------------------------------------------------------------------

const char *argp_program_version = "bpfcov 0.1";
const char *argp_program_bug_address = "leo";
error_t argp_err_exit_status = 1;

// --------------------------------------------------------------------------------------------------------------------
// Prototypes
// --------------------------------------------------------------------------------------------------------------------

const char *argp_key(int key, char *str);

struct root_args;
typedef int (*callback_t)(struct root_args *args);

static error_t root_parse(int key, char *arg, struct argp_state *state);
void root(int argc, char **argv);

void run_cmd(struct argp_state *state);
static error_t run_parse(int key, char *arg, struct argp_state *state);
int run(struct root_args *args);

int gen(struct root_args *args);

static bool is_bpffs(char *bpffs_path);
static void strip_trailing_char(char *str, char c);
static void replace_with(char *str, const char what, const char with);

// --------------------------------------------------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------------------------------------------------

void print_log(int level, struct root_args *args, const char *fmt, ...);

#define log_erro(args, fmt, ...)                  \
    do                                            \
    {                                             \
        if (DEBUG)                                \
            print_log(0, args, fmt, __VA_ARGS__); \
    } while (0)

#define log_warn(args, fmt, ...)                  \
    do                                            \
    {                                             \
        if (DEBUG)                                \
            print_log(1, args, fmt, __VA_ARGS__); \
    } while (0)

#define log_info(args, fmt, ...)                  \
    do                                            \
    {                                             \
        if (DEBUG)                                \
            print_log(2, args, fmt, __VA_ARGS__); \
    } while (0)

#define log_debu(args, fmt, ...)                  \
    do                                            \
    {                                             \
        if (DEBUG)                                \
            print_log(3, args, fmt, __VA_ARGS__); \
    } while (0)

// --------------------------------------------------------------------------------------------------------------------
// Entrypoint
// --------------------------------------------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    root(argc, argv);

    return 0;
}

// --------------------------------------------------------------------------------------------------------------------
// CLI / bpfcov ...
// --------------------------------------------------------------------------------------------------------------------

#define NUM_PINNED_MAPS 4

struct root_args
{
    char *bpffs;
    char *cov_root;
    char *prog_root;
    char *pin[NUM_PINNED_MAPS];
    int verbosity;
    callback_t command;
    char **program;
};

const char ROOT_BPFFS_OPT_KEY = 0x80;
const char ROOT_BPFFS_OPT_LONG[] = "bpffs";
const char ROOT_BPFFS_OPT_ARG[] = "path";
const char ROOT_VERBOSITY_OPT_KEY = 'v';
const char ROOT_VERBOSITY_OPT_LONG[] = "verbose";
const char ROOT_VERBOSITY_OPT_ARG[] = "level";

static struct argp_option root_opts[] = {
    {"OPTIONS:", 0, 0, OPTION_DOC, 0, 0},
    {ROOT_BPFFS_OPT_LONG, ROOT_BPFFS_OPT_KEY, ROOT_BPFFS_OPT_ARG, 0, "Set the BPF FS path (defaults to /sys/fs/bpf)", 1},
    {

        ROOT_VERBOSITY_OPT_LONG,
        ROOT_VERBOSITY_OPT_KEY,
        ROOT_VERBOSITY_OPT_ARG,
        OPTION_ARG_OPTIONAL,
        "Set the verbosity level (defaults to 0)",
        -1

    },
    {0} // .
};

static char root_docs[] =
    "\n"
    "Obtain coverage from your instrumented eBPF programs."
    "\v"
    "  EXAMPLES:\n"
    "  bpfcov run <program>\n"
    "  bpfcov gen <program>\n"
    "  bpfcov <program>\n";

static struct argp root_argp = {
    .options = root_opts,
    .parser = root_parse,
    .args_doc = "[run|gen] <program>",
    .doc = root_docs,
};

static error_t root_parse(int key, char *arg, struct argp_state *state)
{
    struct root_args *args = state->input;

    char str[2];
    log_debu(args, "root: parsing %s = '%s'\n", argp_key(key, str), arg ? arg : "(null)");

    switch (key)
    {

    // Initialization
    case ARGP_KEY_INIT:
        args->bpffs = "/sys/fs/bpf";
        args->verbosity = 0;
        args->command = NULL;
        args->program = calloc(PATH_MAX, sizeof(char *));
        break;

    case ROOT_BPFFS_OPT_KEY:
        if (strlen(arg) > 0)
        {
            strip_trailing_char(arg, '/');
            args->bpffs = arg;
            break;
        }
        argp_error(state, "option '--%s' requires a %s", ROOT_BPFFS_OPT_LONG, ROOT_BPFFS_OPT_ARG);
        break;

    case ROOT_VERBOSITY_OPT_KEY:
        if (arg)
        {
            errno = 0;
            char *end;
            long num = strtol(arg, &end, 10);
            if (end == arg)
            {
                argp_error(state, "option '--%s' requires a numeric %s", ROOT_VERBOSITY_OPT_LONG, ROOT_VERBOSITY_OPT_ARG);
            }
            if (num < 0 || num > 3)
            {
                argp_error(state, "option '--%s' requires a %s value in [0,3]", ROOT_VERBOSITY_OPT_LONG, ROOT_VERBOSITY_OPT_ARG);
            }

            args->verbosity = (int)num;
        }
        else
        {
            args->verbosity++;
        }
        break;

    case ARGP_KEY_ARG:
        assert(arg);

        if (strncmp(arg, "run", 3) == 0)
        {
            args->command = &run;
            run_cmd(state);
        }
        else if (strncmp(arg, "gen", 3) == 0)
        {
            args->command = &gen;
            // gen_cmd(state);
        }
        else
        {
            args->program[state->arg_num] = arg;
        }

        break;

    // Args validation
    case ARGP_KEY_END:
        if (state->arg_num == 0)
        {
            argp_state_help(state, state->err_stream, ARGP_HELP_STD_HELP);
        }
        if (args->program[0] == NULL)
        {
            // This should never happen
            argp_error(state, "unexpected missing <program>");
        }
        break;

    // Final validations, checks, and settings
    case ARGP_KEY_FINI:
        // Check the BPF filesystem
        if (!is_bpffs(args->bpffs))
        {
            argp_error(state, "the BPF filesystem is not mounted at %s", args->bpffs);
        }

        // Create the coverage directory in the BPF filesystem
        char cov_root[PATH_MAX];
        int cov_root_len = snprintf(cov_root, PATH_MAX, "%s/%s", args->bpffs, "cov");
        if (cov_root_len >= PATH_MAX)
        {
            argp_error(state, "coverage root path too long");
        }
        if (mkdir(cov_root, 0700) && errno != EEXIST)
        {
            argp_error(state, "could not create '%s'", cov_root);
        }
        args->cov_root = cov_root;

        // Obtain the program name and create a directory in the BPF filesystem for it
        char *prog_name = basename(args->program[0]);
        char prog_root[PATH_MAX];
        int prog_root_len = snprintf(prog_root, PATH_MAX, "%s/%s", cov_root, prog_name);
        if (prog_root_len >= PATH_MAX)
        {
            argp_error(state, "program root path too long");
        }
        char *prog_root_sane = strdup(prog_root);
        replace_with(prog_root_sane, '.', '_');
        if (mkdir(prog_root_sane, 0700) && errno != EEXIST)
        {
            argp_error(state, "could not create '%s'", prog_root_sane);
        }
        args->prog_root = prog_root_sane;

        // Create pinning path for the counters map
        char pin_profc[PATH_MAX];
        int pin_profc_len = snprintf(pin_profc, PATH_MAX, "%s/%s", prog_root_sane, "profc");
        if (pin_profc_len >= PATH_MAX)
        {
            argp_error(state, "counters pinning path too long");
        }
        args->pin[0] = pin_profc;

        // Create pinning path for the data map
        char pin_profd[PATH_MAX];
        int pin_profd_len = snprintf(pin_profd, PATH_MAX, "%s/%s", prog_root_sane, "profd");
        if (pin_profd_len >= PATH_MAX)
        {
            argp_error(state, "data pinning path too long");
        }
        args->pin[1] = pin_profd;

        // Create pinning path for the names map
        char pin_profn[PATH_MAX];
        int pin_profn_len = snprintf(pin_profn, PATH_MAX, "%s/%s", prog_root_sane, "profn");
        if (pin_profn_len >= PATH_MAX)
        {
            argp_error(state, "names pinning path too long");
        }
        args->pin[2] = pin_profn;

        // Create pinning path for the coverage mapping header
        char pin_covmap_head[PATH_MAX];
        int pin_covmap_head_len = snprintf(pin_covmap_head, PATH_MAX, "%s/%s", prog_root_sane, "covmap_head");
        if (pin_covmap_head_len >= PATH_MAX)
        {
            argp_error(state, "coverage mapping header path too long");
        }
        args->pin[3] = pin_covmap_head;

        // Check whether the map pinning paths already exist and unpin them in case they do exist
        // Only if current subcommand is not `gen`
        bool is_gen = args->command == &gen;
        int p;
        for (p = 0; p < NUM_PINNED_MAPS && !is_gen; p++)
        {
            if (access(args->pin[p], F_OK) == 0)
            {
                log_warn(args, "unpinning existing map '%s'", args->pin[p]);
                if (unlink(args->pin[p]) != 0)
                {
                    argp_error(state, "could not unpin map '%s'", args->pin[p]);
                }
            }
        }

        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void root(int argc, char **argv)
{
    struct root_args this = {
        .verbosity = 0,
    };
    argp_parse(&root_argp, argc, argv, ARGP_IN_ORDER, NULL, &this);

    if (this.command)
    {
        this.command(&this);
    }
    else
    {
        fprintf(stderr, "TBD\n");
        fprintf(stdout, "root: program = '%s'\n", this.program[0]);
        // run(&this);
        // gen(&this);
    }
}

// --------------------------------------------------------------------------------------------------------------------
// CLI / bpfcov run ...
// --------------------------------------------------------------------------------------------------------------------

struct run_args
{
    struct root_args *parent;
};

static struct argp_option run_opts[] = {
    {0} // .
};

static char run_docs[] = "\n"
                         "run\n"
                         "\n";

static struct argp run_argp = {
    .options = run_opts,
    .parser = run_parse,
    .args_doc = "<program>",
    .doc = run_docs,
};

static error_t
run_parse(int key, char *arg, struct argp_state *state)
{
    struct run_args *args = state->input;

    assert(args);
    assert(args->parent);

    char str[2];
    log_debu(args->parent, "run: parsing %s = '%s'\n", argp_key(key, str), arg ? arg : "(null)");

    switch (key)
    {
    case ARGP_KEY_ARG:
        args->parent->program[state->arg_num] = arg;
        break;

    case ARGP_KEY_END:
        if (args->parent->program[0] == NULL)
        {
            argp_error(state, "missing <program>");
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void run_cmd(struct argp_state *state)
{
    struct run_args args = {};
    int argc = state->argc - state->next + 1;
    char **argv = &state->argv[state->next - 1];
    char *argv0 = argv[0];

    args.parent = state->input;

    log_debu(args.parent, "run: begin (argc = %d, argv[0] = %s)\n", argc, argv[0]);

    argv[0] = malloc(strlen(state->name) + strlen(" run") + 1);
    if (!argv[0])
    {
        argp_failure(state, 1, ENOMEM, 0);
    }
    sprintf(argv[0], "%s run", state->name);

    argp_parse(&run_argp, argc, argv, ARGP_IN_ORDER, &argc, &args);

    free(argv[0]);

    argv[0] = argv0;

    state->next += argc - 1;

    log_debu(args.parent, "run: end (next = %d, argv[next] = %s)\n", state->next, state->argv[state->next]);
}

// --------------------------------------------------------------------------------------------------------------------
// Miscellaneous
// --------------------------------------------------------------------------------------------------------------------

const char *argp_key(int key, char *str)
{
    str[0] = key;
    str[1] = 0;

    switch (key)
    {
    case ARGP_KEY_ARG:
        return "ARGP_KEY_ARG";
    case ARGP_KEY_ARGS:
        return "ARGP_KEY_ARGS";
    case ARGP_KEY_END:
        return "ARGP_KEY_END";
    case ARGP_KEY_NO_ARGS:
        return "ARGP_KEY_NO_ARGS";
    case ARGP_KEY_INIT:
        return "ARGP_KEY_INIT";
    case ARGP_KEY_SUCCESS:
        return "ARGP_KEY_SUCCESS";
    case ARGP_KEY_ERROR:
        return "ARGP_KEY_ERROR";
    case ARGP_KEY_FINI:
        return "ARGP_KEY_FINI";
    }

    return str;
};

void print_log(int level, struct root_args *args, const char *fmt, ...)
{
    if (args->verbosity < level)
    {
        return;
    }

    const char *qual;
    switch (level)
    {
    case 0:
        qual = "erro";
        break;
    case 1:
        qual = "warn";
        break;
    case 2:
        qual = "info";
        break;
    case 3:
        qual = "debu";
        break;
    default:
        qual = "unkn";
        break;
    }

    va_list argptr;
    FILE *f = level == 0 ? stderr : stdout;
    va_start(argptr, fmt);
    fprintf(f, "bpfcov: %s: ", qual);
    vfprintf(f, fmt, argptr);
    va_end(argptr);
}

static bool is_bpffs(char *bpffs_path)
{
    struct statfs st_fs;

    if (statfs(bpffs_path, &st_fs) < 0)
        return false;

    return st_fs.f_type == BPF_FS_MAGIC;
}

static void strip_trailing_char(char *str, char c)
{
    int last = strlen(str) - 1;
    while (last > 0 && str[last] == c)
    {
        str[last--] = '\0';
    }
}

static void replace_with(char *str, const char what, const char with)
{
    while (*str)
    {
        if (*str == what)
        {
            *str = with;
        }
        str++;
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Implementation
// --------------------------------------------------------------------------------------------------------------------

int run(struct root_args *args)
{
    log_info(args, "executing program '%s'\n", args->program[0]);

    return 0;
}

int gen(struct root_args *args)
{
    log_info(args, "generating from program '%s'\n", args->program[0]);

    return 0;
}