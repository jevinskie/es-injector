#include <os/log.h>
#include <stdio.h>
#include <string.h>

static os_log_t logger;

int main(int argc, const char **argv) {
    printf("test-es-inject-exe: hello from main!\n");
#ifdef __x86_64__
    printf("test-es-inject-exe: arch: x84_64\n");
    os_log(logger, "arch: x84_64\n");
#elif defined(__arm64e__)
    printf("test-es-inject-exe: arch: arm64e\n");
    os_log(logger, "arch: arm64e\n");
#elif defined(__arm64__)
    printf("test-es-inject-exe: arch: arm64\n");
    os_log(logger, "arch: arm64\n");
#else
#error unknown arch
#endif
    logger = os_log_create("vin.je.test-es-injector-exe", "test");
    os_log(logger, "hello from main");
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "-wait")) {
            getc(stdin);
        }
    }
    return 0;
}
