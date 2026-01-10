#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generated.h"

static unsigned long long fnv1a64(const char* s) {
  const unsigned long long FNV_OFFSET = 1469598103934665603ULL;
  const unsigned long long FNV_PRIME = 1099511628211ULL;
  unsigned long long h = FNV_OFFSET;
  if (!s) {
    return h;
  }
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    h ^= (unsigned long long)(*p);
    h *= FNV_PRIME;
  }
  return h;
}

static int looks_like_flag(const char* s) {
  if (!s) return 0;
  size_t n = strlen(s);
  if (n < 6) return 0;
  if (strncmp(s, "FLAG{", 5) != 0) return 0;
  if (s[n - 1] != '}') return 0;
  return 1;
}

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

  char flag_value[64];
  if (looks_like_flag(hidden)) {
    // Use embedded flag string directly.
    snprintf(flag_value, sizeof(flag_value), "%s", hidden);
  } else {
    unsigned long long hv = fnv1a64(hidden);
    snprintf(flag_value, sizeof(flag_value), "FLAG{%016llx}", hv);
  }

  // Emit manifest. The hidden text is marked sensitive at the catalog layer.
  fprintf(fp,
          "{\n"
          "  \"generator_id\": \"gen.c.hidden_text_binary\",\n"
          "  \"outputs\": {\n"
          "    \"flag\": \"%s\",\n"
          "    \"binary_path\": \"%s\",\n"
          "    \"hidden_text\": \"%s\",\n"
          "    \"hidden_checksum\": %u\n"
          "  }\n"
          "}\n",
          flag_value,
          bin_path,
          hidden,
          (unsigned int)sink);
  fclose(fp);

  printf("Generated %s\n", outputs_path);
  return 0;
}
