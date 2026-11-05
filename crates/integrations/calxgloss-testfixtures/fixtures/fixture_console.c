/*
 * fixture_console.c — the calxgloss test fixture console EXE.
 *
 * A small Windows console program (x86-64) built from this source by the
 * `calxgloss-testfixtures` crate's build script, beside the fixture DLLs.
 * The scenario lane (P24) needs a console program it can run for real:
 * one that consumes stdin lines, writes observable files under its run
 * dir, and exits with declared codes — the shapes a scenario exercise
 * needs on the terminal, interaction, exit, and process dimensions.
 * Nothing scenario-specific exists in this program; it is plain console
 * behavior a scenario can rig against.
 *
 * The protocol, one line per interaction:
 *
 *   echo <text>              print <text> to stdout, verbatim
 *   write <path> <text>      write "<text>\n" to <path> (relative to the
 *                            run dir), then acknowledge `wrote <path>` —
 *                            or `write-failed <path>` if the open fails
 *   delete <path>            remove <path>: `deleted <path>`, or
 *                            `missing <path>` when there was nothing
 *   exit <code>              end the run right now with that exit code
 *   spawn <command line>     launch <command line> as a child process,
 *                            acknowledged `spawned <win-pid> <command
 *                            line>`, or `spawn-failed <command line>`
 *                            if the launch fails; the fixture carries
 *                            on reading and never waits on the child
 *   secret                   read the single line that follows and
 *                            acknowledge `typed-bytes:<N>` — the line's
 *                            byte count and nothing else; the secret
 *                            text is never written anywhere. The run
 *                            starts echo-less (below), so what the
 *                            terminal receives is only this count
 *   anything else            `refused: <line>`, and the run carries on —
 *                            a bad interaction is named, never fatal
 *
 * The run clears `ENABLE_ECHO_INPUT` on its console input at start:
 * a Wine console echoes typed lines itself, at a level the host terminal
 * cannot silence, and a scenario capture must carry only what the fixture
 * itself writes — especially when a scripted interaction is a secret
 * whose text must never reach the record (measured on wine-11: clearing
 * the mode keeps line input intact and silences every typed echo).
 *
 * At EOF the run ends with the exit code declared by `--exit-code N` on
 * argv (default 0): both declaration routes — argv and stdin — let a
 * rigged comparison force a named divergence. A malformed `--exit-code`
 * value is refused loudly on stderr with exit 2, never silently treated
 * as 0. stdout is unbuffered so every acknowledgment lands in observation
 * order while the run lives.
 *
 * `--say TEXT` on argv prints TEXT to stdout once, in argv order, right
 * after the identity lines: the terminal dimension's argv declaration
 * route, so a rigged comparison can inject a named output difference
 * through argv alone (P24.7, issue #408). A `--say` stripped of its text
 * is refused like a malformed `--exit-code`: loudly on stderr, exit 2.
 *
 * The identity literals are the contract the fixture crate's console
 * smoke test enforces, the console analogue of the DLL fixture's string
 * literals: a reviewer names this fixture by them, never by a build path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Identity literals the console smoke test must find in the image. */
static const char kTag[] = "calxgloss-fixture-console-v1";
static const char kReady[] = "calxgloss fixture console ready";

/* Strip one trailing newline (and a CR before it) in place. */
static void chomp(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[len-- - 1] = '\0';
}

/* Handle one stdin line. Returns the exit code to end on, or -1 to
 * carry on reading. */
static int handle_line(char *line)
{
    if (strncmp(line, "echo ", 5) == 0) {
        puts(line + 5);
        return -1;
    }
    if (strncmp(line, "write ", 6) == 0) {
        char *rest = line + 6;
        char *space = strchr(rest, ' ');
        char *content = "";
        if (space) {
            *space = '\0';
            content = space + 1;
        }
        FILE *file = fopen(rest, "wb");
        if (file) {
            fputs(content, file);
            fputc('\n', file);
            fclose(file);
            printf("wrote %s\n", rest);
        } else {
            printf("write-failed %s\n", rest);
        }
        return -1;
    }
    if (strncmp(line, "delete ", 7) == 0) {
        const char *path = line + 7;
        printf("%s %s\n", remove(path) == 0 ? "deleted" : "missing", path);
        return -1;
    }
    if (strncmp(line, "spawn ", 6) == 0) {
        char *cmdline = line + 6;
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        memset(&pi, 0, sizeof pi);
        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("spawned %lu %s\n", pi.dwProcessId, cmdline);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("spawn-failed %s\n", cmdline);
        }
        return -1;
    }
    if (strcmp(line, "secret") == 0) {
        /* The declared secret rides the line after the command: its byte
         * count is the only thing acknowledged — the text itself is never
         * written, and with the run echo-less it never reaches the
         * terminal either. */
        char secret[1024];
        if (fgets(secret, sizeof secret, stdin) == NULL) {
            printf("secret-missing\n");
            return -1;
        }
        chomp(secret);
        printf("typed-bytes:%lu\n", (unsigned long)strlen(secret));
        return -1;
    }
    if (strncmp(line, "exit ", 5) == 0) {
        char *end = NULL;
        long code = strtol(line + 5, &end, 10);
        if (end == line + 5 || *end != '\0') {
            printf("refused: %s\n", line);
            return -1;
        }
        return (int)code;
    }
    printf("refused: %s\n", line);
    return -1;
}

int main(int argc, char **argv)
{
    /* Exit code for the EOF route: declared on argv, default 0. A
     * malformed declaration is refused loudly — a rigged comparison
     * must never silently fall back to the default exit code. `--say
     * TEXT` declares an injected output line, printed right after the
     * identity lines in argv order; its own misdeclaration is refused
     * the same loud way. */
    int exit_code = 0;
    static const char *says[16];
    int say_count = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--say") == 0) {
            if (i + 1 >= argc) {
                fputs("fixture console: --say needs text\n", stderr);
                return 2;
            }
            if (say_count >= (int)(sizeof says / sizeof says[0])) {
                fputs("fixture console: too many --say flags\n", stderr);
                return 2;
            }
            says[say_count++] = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--exit-code") != 0)
            continue;
        if (i + 1 >= argc) {
            fputs("fixture console: --exit-code needs a number\n", stderr);
            return 2;
        }
        char *end = NULL;
        long code = strtol(argv[++i], &end, 10);
        if (end == argv[i] || *end != '\0') {
            fprintf(stderr, "fixture console: --exit-code needs a number, got `%s`\n", argv[i]);
            return 2;
        }
        exit_code = (int)code;
    }

    /* Unbuffered stdout: every acknowledgment lands in observation
     * order while the scenario run is still live. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* The run is echo-less from the start: a Wine console echoes
     * typed lines itself and the host terminal cannot silence that, so
     * the fixture clears ENABLE_ECHO_INPUT on its own input. Line input
     * still arrives; only the typed echo goes. */
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD input_mode = 0;
    if (GetConsoleMode(input, &input_mode))
        SetConsoleMode(input, input_mode & ~ENABLE_ECHO_INPUT);

    puts(kReady);
    puts(kTag);
    for (int i = 0; i < say_count; i++)
        puts(says[i]);

    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        chomp(line);
        if (line[0] == '\0')
            continue;
        int code = handle_line(line);
        if (code >= 0)
            return code;
    }
    return exit_code;
}
