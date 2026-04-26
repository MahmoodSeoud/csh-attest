project(
    'csh-attest',
    'c',
    version: '0.1.0',
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
    'src/adapters/kernel_build_id.c',
    'src/adapters/kernel_uname.c',
    'src/adapters/modules_list.c',
    'src/adapters/etc_merkle.c',
    'src/diff.c',
    'src/diff_render.c',
    'src/jcs.c',
    'src/jcs_parse.c',
    'src/sign.c',
]

# libsodium provides crypto_sign_detached (Ed25519) and crypto_hash_sha256
# with auto-detected ARMv8 Crypto Extensions (~10× speedup on Cortex-A53/A55,
# per design doc 4A). Available as a system package on every Linux distro we
# target (libsodium-dev / libsodium-dev / cmocka-dev all in apt + apk).
sodium_dep = dependency('libsodium', required: true)

csh_attest_inc = include_directories('src', 'src/adapters')

# slash is vendored under vendor/slash. Upstream spaceinventor/slash's
# library code uses Linux-only headers (PATH_MAX, DT_DIR) without including
# them, so it fails to build under -Werror on Ubuntu. We never need that
# code at runtime — only the struct shape + macro for the ELF section emit.
# slash_list_add and friends resolve at dlopen time against csh's loaded
# slash. See vendor/slash/slash.h for the full rationale.
slash_inc = include_directories('vendor/slash')
slash_dep = declare_dependency(include_directories: slash_inc)
if is_linux
    add_project_arguments('-DCSH_ATTEST_HAVE_SLASH=1', language: 'c')
    # macOS exposes O_CLOEXEC, fileno, isatty, open_memstream, mkstemp, etc.
    # unconditionally; glibc and musl gate them behind feature-test macros.
    # Set _GNU_SOURCE project-wide on Linux so what works on the dev machine
    # also compiles in CI. Without this, every new translation unit that
    # touches those symbols requires a per-file #define and, until someone
    # remembers, fails Linux CI (sessions 5 and 6 both burned commits to
    # this exact problem). One project-level flag closes the failure class.
    add_project_arguments('-D_GNU_SOURCE=1', language: 'c')
endif

# csh discovers APMs by `libcsh_*` prefix + `.so` suffix (see
# spaceinventor/csh/src/slash_apm.c::file_callback). The output basename must
# match.
csh_attest_lib = shared_library(
    'csh_attest',
    csh_attest_sources,
    include_directories: csh_attest_inc,
    dependencies: [slash_dep, sodium_dep],
    install: true,
    install_dir: get_option('libdir') / 'csh',
)

cmocka_dep = dependency('cmocka', required: false)
if cmocka_dep.found()
    subdir('tests')
endif
