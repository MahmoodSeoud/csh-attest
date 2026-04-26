test_init = executable(
    'test_init',
    'test_init.c',
    '../src/csh_attest.c',
    '../src/attest.c',
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
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep],
    install: false,
)

test('engine', test_engine)

test_jcs = executable(
    'test_jcs',
    'test_jcs.c',
    '../src/jcs.c',
    '../src/attest.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep],
    install: false,
)

test('jcs', test_jcs)

test_jcs_parse = executable(
    'test_jcs_parse',
    'test_jcs_parse.c',
    '../src/jcs.c',
    '../src/jcs_parse.c',
    '../src/attest.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep],
    install: false,
)

test('jcs_parse', test_jcs_parse)

test_diff = executable(
    'test_diff',
    'test_diff.c',
    '../src/csh_attest.c',
    '../src/attest.c',
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

test_sign = executable(
    'test_sign',
    'test_sign.c',
    '../src/sign.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, sodium_dep],
    install: false,
)

test('sign', test_sign)
