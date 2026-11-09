/*
 * Deliberately vulnerable local fixture for the reverse-engineering pack.
 * It is never deployed or executed against a target. The flag string and the
 * argv -> system() path give Ghidra's string/xref and call-graph artifacts
 * something verifiable to recover.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *LAB_FLAG = "flag{ghidra_headless_artifact_proof}";

__attribute__((noinline)) int check_token(const char *t) {
    return strcmp(t, "s3cr3t") == 0;
}

__attribute__((noinline)) void run_command(const char *arg) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %s", arg);
    system(cmd);
}

__attribute__((noinline)) const char *lab_flag(void) {
    return LAB_FLAG;
}

int main(int argc, char **argv) {
    if (argc > 1 && check_token(argv[1])) {
        run_command(argv[1]);
        puts(lab_flag());
    }
    return 0;
}
