#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

struct root_args
{
    char *bpffs;
    int verbosity;
    callback_t command;
    char *program;
};

const char ROOT_BPFFS_OPT_KEY = 0x80;
const char ROOT_VERBOSITY_OPT_KEY = 'v';

static struct argp_option root_opts[] = {
    {"OPTIONS:", 0, 0, OPTION_DOC, 0, 0},
    {"bpffs", ROOT_BPFFS_OPT_KEY, "path", 0, "Set the BPF FS path (defaults to /sys/fs/bpf)", 1},
    {"verbose", ROOT_VERBOSITY_OPT_KEY, "level", OPTION_ARG_OPTIONAL, "Set the verbosity level (defaults to 0)", -1},
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
    case ROOT_BPFFS_OPT_KEY:
        args->bpffs = arg;
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

    // Initialization
    case ARGP_KEY_INIT:
        args->bpffs = "/sys/fs/bpf";
        args->verbosity = 0;
        args->command = NULL;
        args->program = NULL;
        break;

    // Validation
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
// Implementation
// --------------------------------------------------------------------------------------------------------------------

int run(struct root_args *args)
{
    fprintf(stdout, "RUN\n");
    fprintf(stdout, "root: program = '%s'\n", args->program);

    return 0;
}

int gen(struct root_args *args)
{
    fprintf(stdout, "GEN\n");
    fprintf(stdout, "root: program = '%s'\n", args->program);

    return 0;
}