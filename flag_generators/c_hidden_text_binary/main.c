#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generated.h"

static void ensure_out_dir(const char* out_dir) {
  if (!out_dir || out_dir[0] == '\0') {
    out_dir = "out";
  }
  char cmd[1024];
#ifdef _WIN32
  snprintf(cmd, sizeof(cmd), "mkdir %s >nul 2>nul", out_dir);
#else
  snprintf(cmd, sizeof(cmd), "mkdir -p %s >/dev/null 2>&1", out_dir);
#endif
  system(cmd);
}

int main(void) {
  const char* out_dir = getenv("OUT_DIR");
  if (!out_dir || out_dir[0] == '\0') {
    out_dir = "out";
  }
  ensure_out_dir(out_dir);

  // Keep the hidden artifact resident in the binary and referenced at runtime.
  static const char* hidden = HIDDEN_TEXT;
  volatile unsigned int sink = 0;
  for (size_t i = 0; i < strlen(hidden); i++) {
    sink += (unsigned int)(unsigned char)hidden[i];
  }

  char bin_path[1024];
  snprintf(bin_path, sizeof(bin_path), "%s/hiddenbin", out_dir);

  char outputs_path[1024];
  snprintf(outputs_path, sizeof(outputs_path), "%s/outputs.json", out_dir);
  FILE* fp = fopen(outputs_path, "w");
  if (!fp) {
    perror("fopen outputs.json");
    return 3;
  }

  // Emit manifest. The hidden text is marked sensitive at the catalog layer.
  fprintf(fp,
          "{\n"
          "  \"generator_id\": \"gen.c.hidden_text_binary\",\n"
          "  \"outputs\": {\n"
          "    \"binary_path\": \"%s\",\n"
          "    \"hidden_text\": \"%s\",\n"
          "    \"hidden_checksum\": %u\n"
          "  }\n"
          "}\n",
          bin_path,
          hidden,
          (unsigned int)sink);
  fclose(fp);

  printf("Generated %s\n", outputs_path);
  return 0;
}
