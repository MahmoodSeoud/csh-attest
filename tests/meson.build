test_init = executable(
    'test_init',
    'test_init.c',
    '../src/csh_attest.c',
    '../src/attest.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    '../src/diff.c',
    '../src/diff_render.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/sign.c',
    include_directories: [csh_attest_inc, slash_inc],
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('init', test_init)

test_engine = executable(
    'test_engine',
    'test_engine.c',
    '../src/attest.c',
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
    '../src/csh_attest.c',
    '../src/attest.c',
    '../src/adapters/kernel_uname.c',
    '../src/adapters/modules_list.c',
    '../src/adapters/etc_merkle.c',
    '../src/diff.c',
    '../src/diff_render.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/sign.c',
    include_directories: [csh_attest_inc, slash_inc],
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('diff', test_diff)

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
