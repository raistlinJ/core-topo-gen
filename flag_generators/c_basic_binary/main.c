#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ensure_out_dir(const char* out_dir) {
    if (!out_dir || out_dir[0] == '\0') {
        out_dir = "out";
    }
    // Basic portable-ish stub. Assumes out_dir has no shell-unsafe characters.
    char cmd[1024];
    #ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "mkdir %s >nul 2>nul", out_dir);
    #else
    snprintf(cmd, sizeof(cmd), "mkdir -p %s >/dev/null 2>&1", out_dir);
    #endif
    system(cmd);
}

int main(int argc, char** argv) {
    const char* secret = getenv("SECRET");
    const char* out_dir = getenv("OUT_DIR");
    if (!secret || secret[0] == '\0') {
        secret = (argc >= 2) ? argv[1] : NULL;
    }
    if (!secret || secret[0] == '\0') {
        fprintf(stderr, "Missing SECRET env var or argv[1]\n");
        return 2;
    }

    if (!out_dir || out_dir[0] == '\0') {
        out_dir = "out";
    }
    ensure_out_dir(out_dir);

    char bin_path[1024];
    snprintf(bin_path, sizeof(bin_path), "%s/basicbin", out_dir);

    // Minimal demo: write an outputs.json manifest.
    char outputs_path[1024];
    snprintf(outputs_path, sizeof(outputs_path), "%s/outputs.json", out_dir);
    FILE* fp = fopen(outputs_path, "w");
    if (!fp) {
        perror("fopen outputs.json");
        return 3;
    }

    // NOTE: This is a stub generator. It does not embed the secret at compile-time.
    // It demonstrates how a compiled program can emit a structured outputs manifest.
    fprintf(fp,
        "{\n"
        "  \"generator_id\": \"gen.c.basic_binary\",\n"
        "  \"outputs\": {\n"
        "    \"binary_path\": \"%s\"\n"
        "  }\n"
        "}\n",
        bin_path
    );
    fclose(fp);

    printf("Generated outputs manifest at %s\n", outputs_path);
    printf("Hint: provide SECRET to influence runtime behavior (future).\n");
    return 0;
}
