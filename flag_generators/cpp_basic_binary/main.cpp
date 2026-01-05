#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

static void ensure_out_dir(const std::string& out_dir) {
#ifdef _WIN32
  std::string cmd = "mkdir " + out_dir + " >nul 2>nul";
#else
  std::string cmd = "mkdir -p " + out_dir + " >/dev/null 2>&1";
#endif
  std::system(cmd.c_str());
}

int main(int argc, char** argv) {
  std::string seed;
  std::string out_dir = "out";
  const char* env_seed = std::getenv("SEED");
  const char* env_out = std::getenv("OUT_DIR");
  if (env_out && env_out[0] != '\0') {
    out_dir = env_out;
  }
  if (env_seed && env_seed[0] != '\0') {
    seed = env_seed;
  } else if (argc >= 2) {
    seed = argv[1];
  }

  if (seed.empty()) {
    std::cerr << "Missing SEED env var or argv[1]" << std::endl;
    return 2;
  }

  ensure_out_dir(out_dir);

  // Minimal demo: write an outputs.json manifest.
  std::ofstream fp(out_dir + "/outputs.json");
  if (!fp) {
    std::cerr << "Failed to open outputs.json" << std::endl;
    return 3;
  }

  const std::string bin_path = out_dir + "/basiccpp";

    fp << "{\n"
      "  \"generator_id\": \"gen.cpp.basic_binary\",\n"
      "  \"outputs\": {\n"
      "    \"binary_path\": \"" << bin_path << "\"\n"
      "  }\n"
      "}\n";

  std::cout << "Generated outputs manifest at " << (out_dir + "/outputs.json") << std::endl;
  std::cout << "Seed was: " << seed << std::endl;
  return 0;
}
