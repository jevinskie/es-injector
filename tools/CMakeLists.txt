add_executable(es-injector-util es-injector-util.cpp)

target_compile_options(es-injector-util PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(es-injector-util es-injector)

install(TARGETS es-injector-util
    RUNTIME DESTINATION bin
)
