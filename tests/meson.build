test_init = executable(
    'test_init',
    'test_init.c',
    '../src/csh_attest.c',
    '../src/attest.c',
    '../src/jcs.c',
    include_directories: csh_attest_inc,
    dependencies: [cmocka_dep, slash_dep],
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
