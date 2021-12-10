#define _GNU_SOURCE

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

void root(int argc, char **argv);
static error_t root_parse(int key, char *arg, struct argp_state *state);

struct root_args;
typedef int (*callback_t)(struct root_args *args);
int run(struct root_args *args);
int gen(struct root_args *args);

static bool is_bpffs(char *bpffs_path);
static void strip_trailing_char(char *str, char c);
static void replace_with(char *str, const char what, const char with);

// --------------------------------------------------------------------------------------------------------------------
// Entrypoint
// --------------------------------------------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    root(argc, argv);

    return 0;
}

// --------------------------------------------------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------------------------------------------------

#define NUM_PINNED_MAPS 4

struct root_args
{
    char *bpffs;
    char *cov_root;
    char *program;
    char *prog_root;
    char *pin[NUM_PINNED_MAPS];
    int verbosity;
    callback_t command;
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
    {ROOT_VERBOSITY_OPT_LONG, ROOT_VERBOSITY_OPT_KEY, ROOT_VERBOSITY_OPT_ARG, OPTION_ARG_OPTIONAL, "Set the verbosity level (defaults to 0)", -1},
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

    switch (key)
    {

    // Initialization
    case ARGP_KEY_INIT:
        args->bpffs = "/sys/fs/bpf";
        args->verbosity = 0;
        args->command = NULL;
        args->program = NULL;
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
            args->verbosity = atoi(arg);
        }
        else
        {
            args->verbosity++;
        }
        break;

    case ARGP_KEY_ARG:
        assert(arg);

        switch (state->arg_num)
        {
        case 0:
            if (strncmp(arg, "run", 3) == 0)
            {
                args->command = &run;
            }
            else if (strncmp(arg, "gen", 3) == 0)
            {
                args->command = &gen;
            }
            else
            {
                args->program = arg;
            }
            break;

        case 1:
            args->program = arg;
            break;

        default:
            argp_usage(state);
            break;
        }

        break;

    // Args validation
    case ARGP_KEY_END:
        if (state->arg_num == 0)
        {
            argp_state_help(state, state->err_stream, ARGP_HELP_STD_HELP);
        }
        if ((state->arg_num == 2 && !args->command != !args->program) || (state->arg_num == 1 && !args->program))
        {
            argp_usage(state);
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
            argp_error(state, "the path of the coverage root inside the BPF filesystem is too long");
        }
        if (mkdir(cov_root, 0700) && errno != EEXIST)
        {
            argp_error(state, "could not create the coverage root '%s' inside the BPF filesystem", cov_root);
        }
        args->cov_root = cov_root;

        // Obtain the program name and create a directory in the BPF filesystem for it
        char *prog_name = basename(args->program);
        char prog_root[PATH_MAX];
        int prog_root_len = snprintf(prog_root, PATH_MAX, "%s/%s", cov_root, prog_name);
        if (prog_root_len >= PATH_MAX)
        {
            argp_error(state, "the path for the coverage of the current program is too long");
        }
        char *prog_root_sane = strdup(prog_root);
        replace_with(prog_root_sane, '.', '_');
        if (mkdir(prog_root_sane, 0700) && errno != EEXIST)
        {
            argp_error(state, "could not create the program root '%s' inside the BPF filesystem", prog_root_sane);
        }
        args->prog_root = prog_root_sane;

        // Create pinning path for the counters map
        char pin_profc[PATH_MAX];
        int pin_profc_len = snprintf(pin_profc, PATH_MAX, "%s/%s", prog_root_sane, "profc");
        if (pin_profc_len >= PATH_MAX)
        {
            argp_error(state, "the path for pinning the profiling counters of the current program is too long");
        }
        args->pin[0] = pin_profc;

        // Create pinning path for the data map
        char pin_profd[PATH_MAX];
        int pin_profd_len = snprintf(pin_profd, PATH_MAX, "%s/%s", prog_root_sane, "profd");
        if (pin_profd_len >= PATH_MAX)
        {
            argp_error(state, "the path for pinning the profiling data of the current program is too long");
        }
        args->pin[1] = pin_profd;

        // Create pinning path for the names map
        char pin_profn[PATH_MAX];
        int pin_profn_len = snprintf(pin_profn, PATH_MAX, "%s/%s", prog_root_sane, "profn");
        if (pin_profn_len >= PATH_MAX)
        {
            argp_error(state, "the path for pinning the profiling names of the current program is too long");
        }
        args->pin[2] = pin_profn;

        // Create pinning path for the coverage mapping header
        char pin_covmap_head[PATH_MAX];
        int pin_covmap_head_len = snprintf(pin_covmap_head, PATH_MAX, "%s/%s", prog_root_sane, "covmap_head");
        if (pin_covmap_head_len >= PATH_MAX)
        {
            argp_error(state, "the path for pinning the profiling names of the current program is too long");
        }
        args->pin[3] = pin_covmap_head;

        // Check whether the map pinning paths already exist and unpin them in case they do
        int p;
        for (p = 0; p < NUM_PINNED_MAPS; p++)
        {
            if (access(args->pin[p], F_OK) == 0)
            {
                if (unlink(args->pin[p]) != 0)
                {
                    argp_error(state, "could not unpin the map '%s' from the BPF filesystem", args->pin[p]);
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
    struct root_args this;
    argp_parse(&root_argp, argc, argv, ARGP_IN_ORDER, NULL, &this);

    if (this.command)
    {
        this.command(&this);
    }
    else
    {
        fprintf(stderr, "TBD\n");
        // run(&this);
        // gen(&this);
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Miscellaneous
// --------------------------------------------------------------------------------------------------------------------

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
    fprintf(stdout, "RUN\n");
    fprintf(stdout, "root: program = '%s'\n", args->program);
    fprintf(stdout, "root: program = '%s'\n", args->prog_root);

    return 0;
}

int gen(struct root_args *args)
{
    fprintf(stdout, "GEN\n");
    fprintf(stdout, "root: program = '%s'\n", args->program);
    fprintf(stdout, "root: program = '%s'\n", args->prog_root);

    return 0;
}