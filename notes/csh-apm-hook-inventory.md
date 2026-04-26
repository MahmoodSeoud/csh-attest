# csh APM Hook Inventory — Open Question #1 Spike

**Date:** 2026-04-26
**Author:** Session 1 implementation
**Reference design doc:** `~/.gstack/projects/space-sync/mahmood-main-design-20260426-112310.md` (Open Q #1)
**Sources read:**
- `spaceinventor/csh` — `src/slash_apm.c`, `src/slash_apm.h` (commit-current `master`)
- `spaceinventor/libapm_csh` — `src/apm.c`, `include/apm/apm.h`, `include/apm/csh_api.h`, `meson.build`
- `spaceinventor/csh_example` — `src/main_slash.c`, `meson.build`, `README.md`
- `spaceinventor/slash` — `include/slash/slash.h`

## VERDICT: **GO** — greenfield csh APM is viable. No parallel-CLI fallback required.

The csh APM "loading mechanism" is a thin `dlopen()` + three `dlsym()` symbol lookups. There is **no sandbox, no capability gate, no enforced API surface.** Once loaded, an APM runs as code inside the csh process and may call any libc / POSIX / libcsp / libdtp / libsodium symbol available to the host binary. The three hooks the design doc gates implementation on (kernel module enumeration, allowlisted `/etc` walking, custom CSP packet handlers) are all standard Linux userspace; nothing about the csh APM model restricts them.

---

## 1. The csh APM contract (what an APM must export)

The csh loader (`csh/src/slash_apm.c::load_apm`, `::initialize_apm`) requires the `.so` to export exactly three symbols, looked up via `dlsym()`:

| Symbol             | Type           | Required? | Purpose |
|--------------------|----------------|-----------|---------|
| `apm_init_version` | `const int`    | **yes** (loader refuses without it) | ABI version handshake. Must match csh's `APM_INIT_VERSION` (currently `10`, with backward compat to `8`). |
| `libmain`          | `int(void)`    | strongly recommended | Init function. Returns `0` on success, non-zero aborts the load (`exit(1)` in csh). |
| `libinfo`          | `void(void)`   | optional   | Called by `apm info` for per-APM banner output. |

In practice every APM links against `libapm_csh` (the upstream `apm_csh_dep` meson dependency), which **provides a default `libmain` for free**. That default `libmain` walks the linker-section ranges `__start_slash..__stop_slash` and `__start_param..__stop_param`, registering everything that was declared with the `slash_command(...)` and parameter-definition macros, plus `__start_vmem..__stop_vmem` for vmem regions. After all auto-registration succeeds it calls (if defined) the user-supplied weak hook:

```c
__attribute__((weak, visibility("hidden"))) int apm_init(void);
```

This `apm_init` is the **only user-author hook needed** for arbitrary startup code (thread spawn, CSP socket bind, libparam config read, heap precheck, session-dir check). Returning non-zero aborts the load.

Source: `libapm_csh/src/apm.c:53–121` (default `libmain`), `libapm_csh/include/apm/apm.h:13` (the `apm_init` declaration).

## 2. Capability matrix vs. design-doc Open Q #1 hooks

### (a) Kernel module enumeration — **GO**

The csh APM API does **not** expose a kmod helper, but it does not need to. An APM is dynamically loaded into the csh process and inherits its privileges. It can:

- Read `/proc/modules` (text, line-based, format `name size used by deps state addr`).
- Walk `/sys/module/<name>/{srcversion, taint, refcnt, version, parameters/}`.
- Optionally link `libkmod` (`pkg-config --libs libkmod`) for typed iteration with vermagic / signature checking — but for v1 a tight `/proc/modules` + `/sys/module` reader is sufficient and dependency-free.

Risk: none. We add `read("/proc/modules")` to the `modules.list` field's `emit_fn` row in the `attest_field_t` table. `libcsp_kmod` adapter is a single C file.

### (b) Allowlisted `/etc` walking — **GO**

csh itself ships `walkdir.c`/`walkdir.h` (used by `apm load`'s search path traversal and the `manual` completer). It is GPL/MIT-compatible and we may either vendor it or use raw `opendir`/`readdir`/`fstatat`/`openat` directly. Either way:

- POSIX `opendir`/`fstatat(O_NOFOLLOW)` lets us walk an explicit allowlist (NOT the whole `/etc`).
- `readlinkat` lets us decide per-entry whether to follow symlinks (the test plan stipulates "walk target, NOT the link" for `/etc` symlinks).
- File contents stream into SHA-256 with `libsodium` `crypto_hash_sha256_state`.

Risk: none. Standard userspace.

### (c) Custom CSP packet handlers — **GO**

`csh_example/src/main_slash.c` already proves that an APM can call arbitrary libcsp functions — `aping_cmd` invokes `csp_ping(node, timeout, size, CSP_O_CRC32)` directly. Symmetrically, an APM can:

- `csp_socket_init` / `csp_bind` / `csp_listen` / `csp_accept` to register a listener on our service ID (default `100`, libparam-overridable per design doc 1H).
- Spawn a worker thread inside `apm_init()` to drive that accept loop.
- Use libdtp's `dtp_session_*` / `dtp_client_main` for the resumable manifest transfer (1B).
- Use libparam's parameter-define macros (`PARAM_DEFINE_STATIC_RAM(...)`) so the config knobs `csh_attest_port`, `csh_attest_payload_id`, `csh_attest_session_dir` (1H, 4C) appear under the `list` command for free.

Risk: none. The csh process already pulls libcsp into its address space; APMs link against `csp_dep` (with `partial_dependency(links: false, includes: true)` so we don't double-link the symbols).

## 3. Implications locked for v1

1. **Build target:** `shared_library('csh_attest', ...)` producing `libcsh_attest.so`. csh's `slash_apm.c::file_callback` filters APM candidates by `libcsh_*` prefix and `.so` suffix, so the name **must** start with `libcsh_` (we use `libcsh_attest`).
2. **Default load paths:** `~/.local/lib/csh`, `<dir of csh binary>`, `/usr/lib/csh`, plus any path passed to `apm load -p <path>`. Yocto recipe (1E) ships to `/usr/lib/csh`.
3. **Init order:** the csh-default `libmain` in `libapm_csh` registers slash commands and params first, **then** calls our `apm_init()`. Therefore: heap precheck (4B), session-dir check (4C), and CSP listener thread spawn all belong inside `apm_init()`, not inside an individual command handler. Failing `apm_init` aborts the load (csh `exit(1)`), which is the right semantics — you don't want a half-initialized attestation tool registered.
4. **`apm_init_version` must be `10`** to match current csh master. We pin via `apm_csh_dep` in meson, so this falls out automatically.
5. **Slash commands are declared at file scope** with `slash_command(name, cmd_func, args, help)` (or `slash_command_sub` for subcommands). They live in the `slash` ELF section and are auto-registered. We will register `attest`, `attest-diff` as top-level; sub-options (`--emit`, `--remote`, `--json`, `--sign`) are parsed inside the command function via `optparse_t` (see `csh_example/src/main_slash.c::aping_cmd`).
6. **No daemon process.** v1 ships entirely as the single APM `.so`. The `attest --remote` server side is a CSP listener thread the APM spawns in `apm_init()` of the bird-side csh — not a separate binary.

## 4. What's NOT in the API (and why we don't care)

- No "lifecycle teardown" hook. APMs don't unload at runtime; csh exits, libc unwinds atexit. Our worker thread should be `pthread_detach`'d (or join with a flag at shutdown, but the simple choice is detach).
- No "permission gate." If an operator `apm load`s a malicious `.so`, it has full process privileges. This is a known property of the model — out of scope for csh-attest, in scope for the operator's deployment hygiene.
- No supplied logging facility. We write structured stderr per the design doc's `E0xx:` convention; nothing forces us to use a csh log call.

## 5. Action items (rolled into session 2 plan)

- [ ] Add `apm_csh` as meson dependency: `dependency('apm_csh', fallback: ['apm_csh', 'apm_csh_dep']).as_link_whole()`.
- [ ] Vendor or wrap-fetch `libcsp`, `libparam`, `slash`, `libapm_csh` via meson `subprojects/`. (Session 1: declare deps as `required: false` so the no-op stub builds without them; flip to `required: true` in session 2.)
- [ ] Implement `apm_init()` with the 4B heap precheck and 4C session-dir tmpfs detection in session 2 (after introspection adapters land).

---

## Hand-back summary

- **GO/NO-GO:** GO. The csh APM model imposes zero blockers on any of the three Open-Q #1 capabilities.
- **No fallback CLI needed.** The "parallel CLI shipped alongside csh" mitigation in the design doc is now de-risked.
- **Author burden is the standard libapm_csh contract:** export `apm_init_version`, let `libapm_csh` provide `libmain`, optionally implement `apm_init()` for startup work. That is the entire surface.
