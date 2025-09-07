/***********************************************************************
 * Copyright (c) 2025  Matias Furszyfer (furszy)                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef LIBSECP256K1_UNIT_TEST_H
#define LIBSECP256K1_UNIT_TEST_H

/* --------------------------------------------------------- */
/* Configurable constants                                    */
/* --------------------------------------------------------- */

/* Maximum number of command-line arguments */
#define MAX_ARGS 32
/* Maximum number of parallel jobs */
#define MAX_SUBPROCESSES 16

/* --------------------------------------------------------- */
/* Test Framework API                                        */
/* --------------------------------------------------------- */

typedef void (*test_fn)(void);

struct test_entry {
    const char* name;
    test_fn func;
};

typedef int (*setup_ctx_fn)(void);
typedef int (*teardown_fn)(void);

struct Targets {
    /* Target tests indexes */
    int slots[MAX_ARGS];
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

struct TestFramework {
    /* Command-line args */
    struct Args args;
    /* General tests registry */
    struct test_entry* registry;
    /* Num of tests */
    int num_tests;
    /* Registry for tests that require no context setup */
    struct test_entry* registry_no_ctx;
    /* Specific context setup and teardown functions */
    setup_ctx_fn fn_setup;
    teardown_fn fn_teardown;
};

/* --------------------------------------------------------- */
/* Public API                                                */
/* --------------------------------------------------------- */

/*
 * Initialize the test framework.
 *
 * Must be called before tf_run() and as early as possible in the program.
 * Parses command-line arguments and configures the framework context.
 * The caller must set 'registry' and 'num_tests' before calling.
 *
 * Returns:
 *   EXIT_SUCCESS (0) on success,
 *   EXIT_FAILURE (non-zero) on error.
 */
static int tf_init(struct TestFramework* tf, int argc, char** argv);

/*
 * Run tests based on the provided test framework context.
 *
 * This function uses the configuration stored in the TestFramework
 * (targets, number of processes, iteration count, etc.) to determine
 * which tests to execute and how to execute them.
 *
 * Returns:
 *   EXIT_SUCCESS (0) if all tests passed,
 *   EXIT_FAILURE (non-zero) otherwise.
 */
static int tf_run(struct TestFramework* tf);

#endif /* LIBSECP256K1_UNIT_TEST_H */
