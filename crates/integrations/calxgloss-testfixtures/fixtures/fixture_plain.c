/*
 * fixture_plain.c — a fixture target with no import table at all.
 *
 * Built by the `calxgloss-testfixtures` crate's build script into
 * `fixture_plain.dll` with `-nostdlib`, so the image has named exports
 * but zero imports and no CRT. The P22 trace gate tests point the
 * harness's IAT interposer at it to prove that a target with nothing to
 * interpose on is a reported, survivable condition: no trace, no crash,
 * no hang.
 */

#define EXPORT __attribute__((dllexport))

EXPORT int plain_add(int a, int b)
{
    return a + b;
}
