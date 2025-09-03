/***********************************************************************
 * Copyright (c) 2025  Matias Furszyfer (furszy)                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef LIBSECP256K1_UNIT_TEST_C
#define LIBSECP256K1_UNIT_TEST_C

#include "tests.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

/* Ensure pid_t is defined. Include <sys/types.h> only if necessary (strict C90 mode) */
#if !defined(_PID_T) && !defined(pid_t)
#include <sys/types.h>
#endif

#define MAX_ARGS 20
#define MAX_SUBPROCESSES 16

struct Targets {
    /* Target tests indexes */
    int slots[NUM_TESTS];
    /* Next available slot */
    int size;
};

/* --- Command-line args --- */
struct Args {
    /* 0 => sequential; 1..MAX_SUBPROCESSES => parallel workers */
    int num_processes;
    /* Specific RNG seed */
    const char* custom_seed;
    /* Target tests indexes */
    struct Targets targets;
};

static int parse_jobs_count(const char* key, const char* value, struct Args* out);
static int parse_iterations(const char* arg);
static int parse_target(const char* value, struct Args* out);

/*
 *   Main entry point for handling command-line arguments.
 *
 *   This function is responsible for parsing a single key/value pair
 *   (e.g., -jobs=4) and updating the provided Args struct accordingly.
 *
 *   Developers should extend this function whenever new command-line
 *   options are introduced. Each new argument should be validated,
 *   converted to the appropriate type, and stored in the 'Args' struct.
 */
static int parse_arg(const char* key, const char* value, struct Args* out) {
    /* Number of concurrent tasks */
    if (strcmp(key, "j") == 0 || strcmp(key, "jobs") == 0) {
        return parse_jobs_count(key, value, out);
    }
    /* Number of iterations */
    if (strcmp(key, "iter") == 0 || strcmp(key, "iterations") == 0) {
        return parse_iterations(value);
    }
    /* Custom seed */
    if (strcmp(key, "seed") == 0) {
        out->custom_seed = (!value || strcmp(value, "NULL") == 0) ? NULL : value;
        return 0;
    }
    /* Test target */
    if (strcmp(key, "t") == 0 || strcmp(key, "target") == 0) {
        return parse_target(value, out);
    }

    /* Unknown key: report just so typos don’t silently pass. */
    printf("Unknown argument '-%s=%s'\n", key, value);
    return 0;
}

static void help(void) {
    printf("Usage: ./tests [options]\n\n");
    printf("Run the test suite for the project with optional configuration.\n\n");
    printf("Options:\n");
    printf("    -help                           Show this help message and exit\n");
    printf("    -j=<num>, -jobs=<num>           Number of parallel worker processes (default: 0 = sequential)\n");
    printf("    -iter=<num>, -iterations=<num>  Number of iterations for each test (default: 64)\n");
    printf("    -seed=<hex>                     Set a specific RNG seed (default: random)\n");
    printf("    -target=<test name>, -t=<name>  Run a specific test (can be provided multiple times)\n");
    printf("\n");
    printf("Notes:\n");
    printf("    - All arguments must be provided in the form '-key=value'.\n");
    printf("    - Unknown arguments are reported but ignored.\n");
    printf("    - Sequential execution occurs if -jobs=0 or unspecified.\n");
    printf("    - The first two positional arguments (iterations and seed) are also supported for backward compatibility.\n");
}

static int parse_jobs_count(const char* key, const char* value, struct Args* out) {
    char* ptr_val;
    long val = strtol(value, &ptr_val, 10); /* base 10 */
    if (*ptr_val != '\0') {
        printf("Invalid number for -%s=%s\n", key, value);
        return -1;
    }
    if (val < 0 || val > MAX_SUBPROCESSES) {
        printf("Arg '-%s' out of range: '%ld'. Range: 0..%d\n", key, val, MAX_SUBPROCESSES);
        return -1;
    }
    out->num_processes = (int) val;
    return 0;
}

static int parse_iterations(const char* arg) {
    /* find iteration count */
    if (arg) {
        COUNT = (int) strtol(arg, NULL, 0);
    } else {
        const char* env = getenv("SECP256K1_TEST_ITERS");
        if (env && strlen(env) > 0) {
            COUNT = (int) strtol(env, NULL, 0);
        }
    }
    if (COUNT <= 0) {
        fputs("An iteration count of 0 or less is not allowed.\n", stderr);
        return -1;
    }
    printf("test count = %i\n", COUNT);
    return 0;
}

static int parse_target(const char* value, struct Args* out) {
    int idx_test;
    if (out->targets.size > (int) NUM_TESTS) {
        printf("Too many -target arguments (max: %d)\n", (int) NUM_TESTS);
        return -1;
    }
    /* Find test index in the registry */
    for (idx_test = 0; idx_test < (int) NUM_TESTS; idx_test++) {
        if (strcmp(value, tests[idx_test].name) == 0) break;
    }
    if (idx_test == (int) NUM_TESTS) {
        printf("Target test not found '%s'\n", value);
        return -1;
    }
    out->targets.slots[out->targets.size] = idx_test;
    out->targets.size++;
    return 0;
}

/* Read args; all must be "-key=value" */
static int read_args(int argc, char** argv, int start, struct Args* out) {
    int i;
    char* index_equality;
    for (i = start; i < argc; i++) {
        const char* arg = argv[i];
        if (!arg || arg[0] != '-') {
            printf("Arg '%s' must start with '-'\n", arg ? arg : "(null)");
            return -1;
        }

        index_equality = strchr(arg, '=');
        if (index_equality == NULL || index_equality == arg+1) {
            printf("Arg %s must be -key=value\n", arg);
            return -1;
        }

        *index_equality = '\0';
        if (parse_arg(arg + 1, index_equality + 1, out) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Setup test environment */
static void setup(void) {
    /* Create a global context available to all tests */
    CTX = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    /* Randomize the context only with probability 15/16
       to make sure we test without context randomization from time to time.
       TODO Reconsider this when recalibrating the tests. */
    if (testrand_bits(4)) {
        unsigned char rand32[32];
        testrand256(rand32);
        CHECK(secp256k1_context_randomize(CTX, rand32));
    }
    /* Make a writable copy of secp256k1_context_static in order to test the effect of API functions
       that write to the context. The API does not support cloning the static context, so we use
       memcpy instead. The user is not supposed to copy a context but we should still ensure that
       the API functions handle copies of the static context gracefully. */
    STATIC_CTX = malloc(sizeof(*secp256k1_context_static));
    CHECK(STATIC_CTX != NULL);
    memcpy(STATIC_CTX, secp256k1_context_static, sizeof(secp256k1_context));
    CHECK(!secp256k1_context_is_proper(STATIC_CTX));
}

/* Shutdown test environment */
static void teardown(void) {
    free(STATIC_CTX);
    secp256k1_context_destroy(CTX);

    testrand_finish();
}

static void run_test(const struct test_entry* t) {
    printf("Running %s..\n", t->name);
    t->func();
    printf("%s PASSED\n", t->name);
}

struct MiniTestContext {
    /* Sub-Processes Info */
    pid_t workers[MAX_SUBPROCESSES];
    int pipes[MAX_SUBPROCESSES][2];
    /* Next worker to send work */
    int worker_idx;
    /* Parent process exit status */
    int status;
};

int main(int argc, char** argv) {
    int run_all = 1;
    /* Command-line args */
    struct Args args = {/*num_processes=*/0, /*custom_seed=*/NULL, /*targets=*/{{0}, 0}};
    /* Test context */
    struct MiniTestContext ctx;
    /* Loop iterator */
    int it, it_end;
    /* Test entry iterator */
    struct test_entry* t;
    /* Accumulated test time */
    struct timeval start, end;
    double total_sec;
    gettimeofday(&start, NULL);

    /* Disable buffering for stdout to improve reliability of getting
     * diagnostic information. Happens right at the start of main because
     * setbuf must be used before any other operation on the stream. */
    setbuf(stdout, NULL);
    /* Also disable buffering for stderr because it's not guaranteed that it's
     * unbuffered on all systems. */
    setbuf(stderr, NULL);

    /* Parse command-line args */
    if (argc > 1) {
        int named_arg_start = 1; /* index to begin processing named arguments */
        if (argc > MAX_ARGS) {
            printf("Too many command-line arguments (max: %d)\n", MAX_ARGS);
            _exit(EXIT_FAILURE);
        }

        /* Check if we need to print help */
        if (argv[1] && strcmp(argv[1], "-help") == 0) {
            help();
            _exit(EXIT_SUCCESS);
        }

        /* Compatibility Note: The first two args were the number of iterations and the seed. */
        /* If provided, parse them and adjust the starting index for named arguments accordingly. */
        if (argv[1] && argv[1][0] != '-') {
            int has_seed = argc > 2 && argv[2] && argv[2][0] != '-';
            if (parse_iterations(argv[1]) != 0) _exit(EXIT_FAILURE);
            if (has_seed) args.custom_seed = (strcmp(argv[2], "NULL") == 0) ? NULL : argv[2];
            named_arg_start = has_seed ? 3 : 2;
        }
        if (read_args(argc, argv, named_arg_start, &args) != 0) {
            _exit(EXIT_FAILURE);
        }

        /* Disable run_all if there are specific targets */
        if (args.targets.size != 0) run_all = 0;
    }

    /* run test RNG tests (must run before we really initialize the test RNG) */
    /* Note: currently, these tests are executed sequentially because there */
    /* is really only one test. */
    for (t = tests_no_ctx; t->name; t++) {
        if (run_all) { /* future: support filtering */
            run_test(t);
        }
    }

    /* Initialize test RNG and library contexts */
    testrand_init(args.custom_seed);
    setup();

    /* Sequential run */
    if (args.num_processes == 0) {
        if (run_all) for (t = tests; t->name; t++) run_test(t);
        else {
            /* Run specific targets */
            for (it = 0; it < args.targets.size; it++) {
                run_test(&tests[args.targets.slots[it]]);
            }
        }

        /* Print accumulated time */
        gettimeofday(&end, NULL);
        total_sec = (double)(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        printf("Total execution time: %.3f seconds\n", total_sec);

        teardown();
        return EXIT_SUCCESS;
    }

    /* Parallel run */
    /* Launch worker processes */
    for (it = 0; it < args.num_processes; it++) {
        pid_t pid;
        if (pipe(ctx.pipes[it]) != 0) {
            perror("Error during pipe setup");
            _exit(EXIT_FAILURE);
        }

        pid = fork();
        if (pid < 0) {
            perror("Error during process fork");
            _exit(EXIT_FAILURE);
        }

        if (pid == 0) {
            /* Child worker: run tests assigned via pipe */
            int idx;
            close(ctx.pipes[it][1]); /* Close write end */
            while (read(ctx.pipes[it][0], &idx, sizeof(idx)) == sizeof(idx)) {
                run_test(&tests[idx]);
            }
            _exit(EXIT_SUCCESS);
        } else {
            /* Parent: save worker pid */
            close(ctx.pipes[it][0]); /* Close read end */
            ctx.workers[it] = pid;
        }
    }

    /* Now that we have all sub-processes, distribute workload in round-robin */
    ctx.worker_idx = 0;
    it_end = run_all ? (int) NUM_TESTS : args.targets.size;
    for (it = 0; it < it_end; it++) {
        /* If not run_all, take the test from the specified targets */
        int idx = run_all ? it : args.targets.slots[it];
        write(ctx.pipes[ctx.worker_idx][1], &idx, sizeof(idx));
        if (++ctx.worker_idx >= args.num_processes) ctx.worker_idx = 0;
    }

    /* Close all pipes to signal workers to exit */
    for (it = 0; it < args.num_processes; it++) close(ctx.pipes[it][1]);
    /* Wait for all workers */
    for (it = 0; it < args.num_processes; it++) waitpid(ctx.workers[it], &ctx.status, 0);

    /* Print accumulated time */
    gettimeofday(&end, NULL);
    total_sec = (double)(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    printf("Total execution time: %.3f seconds\n", total_sec);

    teardown();
    return EXIT_SUCCESS;
}

#endif /* LIBSECP256K1_UNIT_TEST_C */
