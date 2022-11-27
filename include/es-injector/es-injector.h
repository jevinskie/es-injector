#pragma once

#include <string>
#include <vector>

void run_injector(std::vector<std::string> injected_env_vars,
                  std::vector<std::string> target_executables);
