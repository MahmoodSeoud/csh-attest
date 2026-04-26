# Source list common to the three test binaries that link csh_attest.c
# (test_init, test_diff, test_verify). On Linux this also pulls in the
# CSP server + client TUs that csh_attest.c references via #ifdef __linux__;
# without them the tests would fail to link.
csh_attest_test_sources = [
    '../src/csh_attest.c',
    '../src/attest.c',
    '../src/adapters/kernel_build_id.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    '../src/diff.c',
    '../src/diff_render.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/sign.c',
]
csh_attest_test_deps = [cmocka_dep, sodium_dep]
if is_linux
    csh_attest_test_sources += [
        '../src/csp_server.c',
        '../src/csp_client.c',
        # Link-time stub for vmem_add (referenced unconditionally by
        # libapm_csh::libmain, runtime-guarded by the empty vmem section).
        # Required for any test binary that pulls in csh_attest_test_sources
        # because apm_csh_dep below uses .as_link_whole().
        'apm_test_stubs.c',
    ]
    csh_attest_test_deps += csp_dep
    # Same upstream libmain that csh_attest_lib links — keeps the test build
    # exercising the same dispatch path the production .so does.
    csh_attest_test_deps += apm_csh_dep
endif

test_init = executable(
    'test_init',
    'test_init.c',
    csh_attest_test_sources,
    include_directories: [csh_attest_inc, slash_inc],
    dependencies: csh_attest_test_deps,
    install: false,
)

test('init', test_init)

test_engine = executable(
    'test_engine',
    'test_engine.c',
    '../src/attest.c',
    '../src/adapters/kernel_build_id.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    '../src/jcs.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('engine', test_engine)

test_jcs = executable(
    'test_jcs',
    'test_jcs.c',
    '../src/jcs.c',
    '../src/attest.c',
    '../src/adapters/kernel_build_id.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('jcs', test_jcs)

test_jcs_parse = executable(
    'test_jcs_parse',
    'test_jcs_parse.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/attest.c',
    '../src/adapters/kernel_build_id.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('jcs_parse', test_jcs_parse)

test_diff = executable(
    'test_diff',
    'test_diff.c',
    csh_attest_test_sources,
    include_directories: [csh_attest_inc, slash_inc],
    dependencies: csh_attest_test_deps,
    install: false,
)

test('diff', test_diff)

test_kernel_build_id = executable(
    'test_kernel_build_id',
    'test_kernel_build_id.c',
    '../src/adapters/kernel_build_id.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep],
    install: false,
)

test('kernel_build_id', test_kernel_build_id)

test_modules_list = executable(
    'test_modules_list',
    'test_modules_list.c',
    '../src/adapters/modules_list.c',
    '../src/jcs.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep],
    install: false,
)

test('modules_list', test_modules_list)

test_etc_merkle = executable(
    'test_etc_merkle',
    'test_etc_merkle.c',
    '../src/adapters/etc_merkle.c',
    '../src/jcs.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('etc_merkle', test_etc_merkle)

# Cross-language interop: round-trip cyberphone reference vectors
# through our parser+emitter pair (design doc 3B-A).
test_jcs_vectors = executable(
    'test_jcs_vectors',
    'test_jcs_vectors.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/attest.c',
    '../src/adapters/kernel_build_id.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    c_args: ['-DJCS_VECTORS_DIR="' + meson.current_source_dir() + '/jcs/vectors"'],
    install: false,
)

test('jcs_vectors', test_jcs_vectors)

test_sign = executable(
    'test_sign',
    'test_sign.c',
    '../src/sign.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('sign', test_sign)

# Exercises the attest_verify_run driver end-to-end: builds a real signed
# envelope through the canonical emitter, writes it + a pubkey to disk,
# drives the run function with synthetic argvs, asserts on exit codes +
# stderr text. Same TU set as test_diff because the driver lives in
# csh_attest.c and pulls in JCS parse + sign + adapters transitively.
test_verify = executable(
    'test_verify',
    'test_verify.c',
    csh_attest_test_sources,
    include_directories: [csh_attest_inc, slash_inc],
    dependencies: csh_attest_test_deps,
    install: false,
)

test('verify', test_verify)

# End-to-end loopback integration test: brings up CSP + the bird-side
# listener thread, then drives attest_remote_run from the same process
# through libcsp's loopback interface. Linux-only — libcsp doesn't build
# on macOS, and the test depends on the same TUs csh_attest.c does on
# Linux (csp_server.c, csp_client.c).
if is_linux
    test_remote = executable(
        'test_remote',
        'test_remote.c',
        csh_attest_test_sources,
        include_directories: [csh_attest_inc, slash_inc],
        dependencies: csh_attest_test_deps,
        install: false,
    )

    test('remote', test_remote)
endif
