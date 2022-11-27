#pragma once

#include <string>
#include <vector>

void run_injector(const std::vector<std::string> &injected_env_vars,
                  const std::vector<std::string> &target_executables);
