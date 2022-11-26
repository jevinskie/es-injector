#include <stdio.h>
#include <os/log.h>

static os_log_t logger;

__attribute__((constructor))
void init_test_es_injector_lib(void) {
    printf("test-es-inject-lib: hello from ctor!\n");
    logger = os_log_create("vin.je.test-es-injector-lib", "test");
    os_log(logger, "hello from ctor");
}

__attribute__((destructor))
void fini_test_es_injector_lib(void) {
    printf("test-es-inject-lib: bye from dtor!\n");
    logger = os_log_create("vin.je.test-es-injector-lib", "test");
    os_log(logger, "bye from dtor");
}
