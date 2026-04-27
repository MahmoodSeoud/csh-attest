/*
 * Mission allowlist loader implementation. See config.h for the API +
 * design contract.
 *
 * Tier 1 (compile-time defaults) wired through; Tier 2 (runtime
 * paths.allow) is reserved as a stub that returns ATTEST_CONFIG_E_IO
 * with errno=ENOENT — same shape as "no config file present", which
 * triggers the Tier 1 fallback. Piece 6 will replace the stub with a
 * real parser.
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "config_defaults.h"

/* ------------------------------------------------------------------ */
/* Path validation (Tier 2)                                            */
/* ------------------------------------------------------------------ */

static int has_dotdot_segment(const char *path)
{
    /*
     * Reject path containing a ".." path segment. We're strict: any
     * occurrence of "/..", "../" or a path equal to ".." or starting
     * "../" rejects. This catches both the canonical traversal pattern
     * and the boundary cases where a literal "..." filename or a name
     * like "..foo" would otherwise be ambiguous to a substring search.
     */
    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '\0' || p[2] == '/') &&
            (p == path || *(p - 1) == '/')) {
            return 1;
        }
        p++;
    }
    return 0;
}

static int has_forbidden_prefix(const char *path)
{
    static const char *const FORBIDDEN[] = {
        "/proc/", "/sys/", "/dev/",
        NULL,
    };
    /* Bare "/proc", "/sys", "/dev" without trailing slash are also forbidden
     * — those are the directories themselves, hashing them is meaningless
     * AND they're symlinks/special-FS roots on Linux. */
    static const char *const FORBIDDEN_EXACT[] = {
        "/proc", "/sys", "/dev",
        NULL,
    };
    for (size_t i = 0; FORBIDDEN[i]; i++) {
        size_t len = strlen(FORBIDDEN[i]);
        if (strncmp(path, FORBIDDEN[i], len) == 0) {
            return 1;
        }
    }
    for (size_t i = 0; FORBIDDEN_EXACT[i]; i++) {
        if (strcmp(path, FORBIDDEN_EXACT[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int attest_config_validate_path(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return ATTEST_CONFIG_E_PATH;
    }
    if (path[0] != '/') {
        return ATTEST_CONFIG_E_PATH;
    }
    if (has_dotdot_segment(path)) {
        return ATTEST_CONFIG_E_PATH;
    }
    if (has_forbidden_prefix(path)) {
        return ATTEST_CONFIG_E_PATH;
    }
    return ATTEST_CONFIG_OK;
}

/* ------------------------------------------------------------------ */
/* Path list construction — sort + dedup + cap                         */
/* ------------------------------------------------------------------ */

static int path_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void path_list_init(attest_path_list_t *l)
{
    l->paths = NULL;
    l->n = 0;
}

static void path_list_free(attest_path_list_t *l)
{
    if (l == NULL) {
        return;
    }
    for (size_t i = 0; i < l->n; i++) {
        free(l->paths[i]);
    }
    free(l->paths);
    l->paths = NULL;
    l->n = 0;
}

int attest_config_path_list_from_array(attest_path_list_t *out,
                                       const char *const *paths,
                                       int validate)
{
    if (out == NULL) {
        return ATTEST_CONFIG_E_PATH;
    }
    path_list_init(out);
    if (paths == NULL) {
        return ATTEST_CONFIG_OK;
    }

    /* First pass: count + validate. */
    size_t n = 0;
    for (const char *const *p = paths; *p != NULL; p++) {
        if (validate) {
            int rc = attest_config_validate_path(*p);
            if (rc != ATTEST_CONFIG_OK) {
                return rc;
            }
        }
        n++;
    }
    if (n > ATTEST_CONFIG_MAX_PATHS_PER_KIND) {
        return ATTEST_CONFIG_E106;
    }
    if (n == 0) {
        return ATTEST_CONFIG_OK;
    }

    /* Allocate + copy. */
    char **owned = calloc(n, sizeof(char *));
    if (owned == NULL) {
        return ATTEST_CONFIG_E_OOM;
    }
    for (size_t i = 0; i < n; i++) {
        owned[i] = strdup(paths[i]);
        if (owned[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(owned[j]);
            }
            free(owned);
            return ATTEST_CONFIG_E_OOM;
        }
    }

    /* Sort byte-wise. */
    qsort(owned, n, sizeof(char *), path_cmp);

    /* Dedup in place. */
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (w == 0 || strcmp(owned[w - 1], owned[i]) != 0) {
            if (w != i) {
                owned[w] = owned[i];
            }
            w++;
        } else {
            free(owned[i]);
        }
    }

    out->paths = owned;
    out->n = w;
    return ATTEST_CONFIG_OK;
}

/* ------------------------------------------------------------------ */
/* Top-level loader                                                    */
/* ------------------------------------------------------------------ */

/*
 * Tier 2 loader stub. Piece 6 replaces this with a real parser. For now,
 * always returns "no Tier 2 config" so the caller falls back to Tier 1.
 *
 * Returning a positive sentinel (1) distinguishes "no Tier 2 file
 * present" from genuine errors (negative codes).
 */
static int try_load_tier2(attest_config_t *out)
{
    (void)out;
    return 1;
}

int attest_config_load(attest_config_t *out)
{
    if (out == NULL) {
        return ATTEST_CONFIG_E_PATH;
    }
    memset(out, 0, sizeof(*out));

    /* Try Tier 2 first; on "no file" sentinel, fall through to Tier 1. */
    int t2 = try_load_tier2(out);
    if (t2 == ATTEST_CONFIG_OK) {
        return ATTEST_CONFIG_OK;
    }
    if (t2 < 0) {
        attest_config_free(out);
        return t2;
    }

    /* Tier 1 fallback. */
    int rc = attest_config_path_list_from_array(
        &out->binaries, CONFIG_DEFAULT_BINARIES_PATHS, /*validate=*/0);
    if (rc != ATTEST_CONFIG_OK) {
        attest_config_free(out);
        return rc;
    }
    rc = attest_config_path_list_from_array(
        &out->files, CONFIG_DEFAULT_FILES_PATHS, /*validate=*/0);
    if (rc != ATTEST_CONFIG_OK) {
        attest_config_free(out);
        return rc;
    }
    return ATTEST_CONFIG_OK;
}

void attest_config_free(attest_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    path_list_free(&cfg->binaries);
    path_list_free(&cfg->files);
    free(cfg->paths_allow_path);
    cfg->paths_allow_path = NULL;
}

/* ------------------------------------------------------------------ */
/* Process-wide cache                                                  */
/* ------------------------------------------------------------------ */

static attest_config_t g_config;
static int g_config_initialized = 0;
static int g_config_load_rc = ATTEST_CONFIG_OK;

const attest_config_t *attest_config_get(void)
{
    if (!g_config_initialized) {
        g_config_load_rc = attest_config_load(&g_config);
        g_config_initialized = 1;
    }
    if (g_config_load_rc != ATTEST_CONFIG_OK) {
        return NULL;
    }
    return &g_config;
}

void attest_config_reset_cache_for_testing(void)
{
    if (g_config_initialized && g_config_load_rc == ATTEST_CONFIG_OK) {
        attest_config_free(&g_config);
    }
    memset(&g_config, 0, sizeof(g_config));
    g_config_initialized = 0;
    g_config_load_rc = ATTEST_CONFIG_OK;
}
