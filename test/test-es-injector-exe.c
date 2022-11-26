#include <os/log.h>
#include <stdio.h>

static os_log_t logger;

int main(void) {
    printf("test-es-inject-exe: hello from main!\n");
    logger = os_log_create("vin.je.test-es-injector-exe", "test");
    os_log(logger, "hello from main");
    return 0;
}
