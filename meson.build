project(
    'csh-attest',
    'c',
    version: '0.2.0',
    license: 'Apache-2.0',
    default_options: [
        # gnu11 (NOT c11) so the `endian.h` GNU extensions
        # (htobe32 / be32toh / etc) are visible without each TU having to
        # pre-declare _GNU_SOURCE. libcsp's wire-format code uses these
        # extensively; under strict c11 its build fails with
        # `implicit-declaration` -Werror. Our own code already assumed
        # _GNU_SOURCE on Linux (set as a project arg below); switching to
        # gnu11 makes that universal across subprojects too.
        'c_std=gnu11',
        'warning_level=3',
        'werror=true',
        'b_ndebug=if-release',
        # libcsp tuning. Defaults are tuned for tiny embedded targets — too
        # small for a 32 KB attestation manifest. Mirrors dipp-apm's pinned
        # values so the FlatSat ↔ bird ABI stays consistent within the
        # DISCO-2 mission's CSP fabric.
        # buffer_size: bytes per CSP packet. 2048 lets a typical manifest
        #   (~2-4 KB once we drop modules.list lines) fit in 1-2 packets.
        # use_rdp:     left enabled (libcsp default) so a future minor can
        #   wire RDP for real-radio retransmit without re-tuning the build.
        #   v0.1.x's --remote uses plain CSP + a 4-byte length prefix; RDP
        #   is compiled into libcsp but unused in our protocol path.
        # have_stdio:  enables csp_print() to actually print, which the
        #   sample CSP loopback harness uses for setup-time diagnostics.
        'csp:buffer_size=2048',
        'csp:buffer_count=15',
        'csp:use_rdp=true',
        'csp:have_stdio=true',
        # port_max_bind is the highest CSP port number that can be bound.
        # libcsp's default of 16 leaves room for the standard service ports
        # (0-7 reserved for ping/ps/memfree/etc, 8 for CMP) but rejects our
        # ATTEST_CSP_PORT=100 (per design doc 1H). Bumping to 128 puts our
        # port well clear of the standard range while staying inside an
        # 8-bit address space. Memory cost: (128+2) * sizeof(csp_port_t) =
        # ~2 KB of static storage in libcsp.
        'csp:port_max_bind=128',
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

# CSP transport sources (bird-side server + ground-side client) compile only
# on Linux. macOS dev builds skip them — libcsp's POSIX driver doesn't
# compile under darwin clang -Werror. The corresponding code in
# csh_attest.c is gated on `#ifdef __linux__`.
csh_attest_csp_sources = [
    'src/csp_server.c',
    'src/csp_client.c',
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

# Make our vendored slash the resolution target for any subproject that does
# `dependency('slash', fallback: ['slash', 'slash_dep'], required: false)`.
# libapm_csh does exactly that — without this override its `dependency()`
# call would fail to find slash, APM_HAVE_SLASH would stay unset, and its
# libmain would compile out the slash-section walker that registers our
# attest / attest-diff / hello commands. Override gives libapm_csh the
# headers it needs without us having to add a third .wrap file.
meson.override_dependency('slash', slash_dep)

# libcsp subproject (per subprojects/csp.wrap). Linux-only for now — libcsp's
# POSIX driver doesn't compile on macOS clang under our -Werror policy.
# macOS keeps the no-CSP dev build via the `is_linux` gate below; the
# unit-test paths that don't require CSP still run there.
#
# libapm_csh (subprojects/apm_csh.wrap) is referenced from step 2 onward —
# its libmain conflicts with our hand-rolled walker until that swap lands,
# so we hold off declaring the dependency in step 1.
if is_linux
    csp_dep = dependency('csp', fallback: ['csp', 'csp_dep'], required: true)
endif

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
csh_attest_deps = [slash_dep, sodium_dep]
if is_linux
    # Includes the CSP transport surface that the attest --remote command
    # builds on top of (sessions 9+). Linux-only; macOS dev builds skip CSP.
    csh_attest_deps += csp_dep
endif

csh_attest_all_sources = csh_attest_sources
if is_linux
    csh_attest_all_sources += csh_attest_csp_sources
endif

csh_attest_lib = shared_library(
    'csh_attest',
    csh_attest_all_sources,
    include_directories: csh_attest_inc,
    dependencies: csh_attest_deps,
    install: true,
    install_dir: get_option('libdir') / 'csh',
)

cmocka_dep = dependency('cmocka', required: false)
if cmocka_dep.found()
    subdir('tests')
endif
