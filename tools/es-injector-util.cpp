#include <es-injector/es-injector.h>

#include <string>
#include <unistd.h>
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
    parser.add_argument("-d", "--dump").default_value(false).implicit_value(true).help("dump info");

    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        fmt::print(stderr, "Error parsing arguments: {:s}\n", err.what());
        return -2;
    }

    if (geteuid() != 0) {
        fmt::print("needs root, exiting");
        return -3;
    }

    const auto env_vars    = parser.get<std::vector<std::string>>("--env-var");
    const auto executables = parser.get<std::vector<std::string>>("--executable");
    const auto dump        = parser.get<bool>("--dump");
    run_injector(env_vars, executables, dump);

    return -1;
}
