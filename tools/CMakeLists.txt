add_executable(es-injector-util es-injector-util.cpp)

target_compile_options(es-injector-util PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(es-injector-util es-injector argparse fmt)

add_custom_command(TARGET es-injector-util
                   POST_BUILD
                   COMMAND codesign -s - --entitlements ${CMAKE_CURRENT_SOURCE_DIR}/ent.xml $<TARGET_FILE:es-injector-util>
)

install(TARGETS es-injector-util
    RUNTIME DESTINATION bin
)
