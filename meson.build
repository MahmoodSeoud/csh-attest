project(
    'csh-attest',
    'c',
    version: '0.0.1',
    license: 'Apache-2.0',
    default_options: [
        'c_std=c11',
        'warning_level=3',
        'werror=true',
        'b_ndebug=if-release',
    ],
)

# Strict warnings consistent with libapm_csh upstream conventions.
add_project_arguments(
    [
        '-Wstrict-prototypes',
        '-Wmissing-prototypes',
        '-Wmissing-declarations',
        '-Wcast-align',
        '-Wpointer-arith',
        '-Wshadow',
    ],
    language: 'c',
)

# Cross-platform note. Production targets are Linux (Yocto + Ubuntu/Alpine
# x86_64/arm64 prebuilts per design doc 1E). Upstream apm_csh + slash use
# glibc-isms (reallocarray) and lax warnings that fail under macOS clang
# -Werror. macOS is therefore a "compile-check only" dev target: slash is
# skipped (the hello command compiles out) and the .so still produces for
# symbol-table inspection. Linux CI is the source of truth.
is_linux = host_machine.system() == 'linux'

# Our libmain references slash_list_add (resolved at dlopen time against csh's
# already-loaded slash). Linux ld permits undefined symbols in shared objects
# by default; macOS ld errors unless we say so.
if host_machine.system() == 'darwin'
    add_project_link_arguments(
        '-Wl,-undefined,dynamic_lookup',
        language: 'c',
    )
endif

csh_attest_sources = [
    'src/csh_attest.c',
    'src/attest.c',
    'src/jcs.c',
]

csh_attest_inc = include_directories('src')

# slash is consumed as headers only — slash_command(...) emits a `struct
# slash_command` into the `slash` linker section, and our hand-rolled libmain
# walks that section calling csh's slash_list_add() (resolved at dlopen time).
#
# This is a session-2 stand-in for upstream libapm_csh's libmain. apm_csh
# transitively depends on libparam + libcsp (vmem.h is referenced
# unconditionally in apm_csh.c outside #ifdef APM_HAVE_PARAM), wiring which is
# deferred to a later session. The section-walk loop is ~10 lines and gets
# deleted when apm_csh lands.
if is_linux
    slash_dep = dependency(
        'slash',
        fallback: ['slash', 'slash_dep'],
        default_options: ['warning_level=0', 'werror=false', 'builtins=false'],
    ).partial_dependency(links: false, includes: true)
    add_project_arguments('-DCSH_ATTEST_HAVE_SLASH=1', language: 'c')
else
    slash_dep = declare_dependency()
endif

# csh discovers APMs by `libcsh_*` prefix + `.so` suffix (see
# spaceinventor/csh/src/slash_apm.c::file_callback). The output basename must
# match.
csh_attest_lib = shared_library(
    'csh_attest',
    csh_attest_sources,
    include_directories: csh_attest_inc,
    dependencies: [slash_dep],
    install: true,
    install_dir: get_option('libdir') / 'csh',
)

cmocka_dep = dependency('cmocka', required: false)
if cmocka_dep.found()
    subdir('tests')
endif
