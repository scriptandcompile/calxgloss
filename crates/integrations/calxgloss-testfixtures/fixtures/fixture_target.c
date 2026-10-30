/*
 * fixture_target.c — the calxgloss test fixture target binary.
 *
 * A small Windows DLL (x86-64) built from this source by the
 * `calxgloss-testfixtures` crate's build script. Its shape is the contract
 * the Kuna engine tests assert against, and the fixture crate's smoke test
 * enforces it:
 *
 *   * five named exports,
 *   * imports from KERNEL32.dll and msvcrt.dll,
 *   * string literals the engine's string scan must find,
 *   * a switch the compiler lowers to a jump table: a run of 4-byte
 *     self-relative entries in .rdata, reached by a rip-relative `lea`
 *     and an indirect `jmp` in .text.
 *
 * The case bodies write a `volatile` global so the compiler cannot fold
 * the switch into arithmetic — without that, `-O2` optimises the table
 * away and the fixture stops being a jump-table target.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define EXPORT __attribute__((dllexport))

/* String literals the engine's string scan must find. */
static const char kGreeting[] = "calxgloss fixture target: hello";
static const char kTag[] = "calxgloss-fixture-target-v1";
static const char kFormat[] = "fixture counter %d";

static char g_describe_buf[64];
static int g_counter = 0;
static volatile int g_state = 0;

EXPORT int fixture_init(void)
{
    g_counter = 1;
    OutputDebugStringA(kGreeting);
    return g_counter;
}

/* The jump-table switch: one volatile store per case keeps the table. */
EXPORT int fixture_status(int code)
{
    switch (code) {
    case 0:  g_state = g_state + 1;  break;
    case 1:  g_state = g_state + 3;  break;
    case 2:  g_state = g_state + 7;  break;
    case 3:  g_state = g_state * 2;  break;
    case 4:  g_state = g_state - 5;  break;
    case 5:  g_state = g_state ^ 0x5a; break;
    case 6:  g_state = g_state + 11; break;
    case 7:  g_state = g_state * 3;  break;
    case 8:  g_state = g_state - 13; break;
    case 9:  g_state = g_state ^ 0x69; break;
    case 10: g_state = g_state + 17; break;
    case 11: g_state = g_state * 5;  break;
    case 12: g_state = g_state - 19; break;
    case 13: g_state = g_state ^ 0xa5; break;
    case 14: g_state = g_state + 23; break;
    case 15: g_state = g_state * 7;  break;
    default: g_state = 0;            break;
    }
    return g_state;
}

/* Exercises the msvcrt imports (malloc/free/snprintf) and a format string.
 * Note mingw's `snprintf` is a static wrapper that bottoms out in `vfprintf`,
 * so the import table shows `vfprintf` rather than `snprintf`. */
EXPORT const char *fixture_describe(int kind)
{
    char *scratch = (char *)malloc(32);
    if (scratch == NULL) {
        return NULL;
    }
    scratch[0] = (char)kind;
    scratch[1] = '\0';
    snprintf(g_describe_buf, sizeof(g_describe_buf), kFormat, g_counter);
    free(scratch);
    return g_describe_buf;
}

/* Exercises the KERNEL32 import (GetTickCount) and, via puts, the tag
 * string and the msvcrt import. */
EXPORT unsigned int fixture_tick(void)
{
    puts(kTag);
    return GetTickCount();
}

/* Ordered-imports probe for the P22 trace gate: GetTickCount first, then
 * OutputDebugStringA with a data dependency on the first result, so the
 * two calls cannot be reordered. The `probe` dereference lets a null
 * argument fault, supplying a crash case for isolation-retry tests. */
EXPORT unsigned int fixture_ordered(int *probe)
{
    DWORD tick = GetTickCount();
    OutputDebugStringA(tick ? kGreeting : kTag);
    return (unsigned int)*probe;
}
