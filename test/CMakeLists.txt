add_executable(test-es-injector-exe test-es-injector-exe.c)
add_library(test-es-injector-lib SHARED test-es-injector-lib.c)
set_target_properties(test-es-injector-lib PROPERTIES PREFIX "")

install(TARGETS test-es-injector-exe
    RUNTIME DESTINATION bin
)

install(TARGETS test-es-injector-lib
    LIBRARY DESTINATION lib
)
