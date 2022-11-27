#include <es-injector/es-injector.h>

#include <string>
#include <vector>

#include <argparse/argparse.hpp>
#include <fmt/format.h>

int main(int argc, const char **argv) {
    argparse::ArgumentParser parser(getprogname());
    parser.add_argument("-v", "--env-var")
        .nargs(argparse::nargs_pattern::at_least_one)
        .help("injected environment variable");
    parser.add_argument("-e", "--executable")
        .nargs(argparse::nargs_pattern::at_least_one)
        .help("target executable");

    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        fmt::print(stderr, "Error parsing arguments: {:s}\n", err.what());
        return -1;
    }

    auto env_vars    = parser.get<std::vector<std::string>>("--env-var");
    auto executables = parser.get<std::vector<std::string>>("--executable");

    run_injector(env_vars, executables);

    return -1;
}
