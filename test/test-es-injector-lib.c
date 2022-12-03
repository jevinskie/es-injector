#include <os/log.h>
#include <stdio.h>

static os_log_t logger;

__attribute__((constructor)) void init_test_es_injector_lib(void) {
    printf("test-es-inject-lib: hello from ctor!\n");
    logger = os_log_create("vin.je.test-es-injector-lib", "test");
    os_log(logger, "hello from ctor");
#ifdef __x86_64__
    printf("test-es-inject-lib: arch: x84_64\n");
    os_log(logger, "arch: x84_64\n");
#elif defined(__arm64e__)
    printf("test-es-inject-lib: arch: arm64e\n");
    os_log(logger, "arch: arm64e\n");
#elif defined(__arm64__)
    printf("test-es-inject-lib: arch: arm64\n");
    os_log(logger, "arch: arm64\n");
#else
#error unknown arch
#endif
}

__attribute__((destructor)) void fini_test_es_injector_lib(void) {
    printf("test-es-inject-lib: bye from dtor!\n");
    os_log(logger, "bye from dtor");
}
