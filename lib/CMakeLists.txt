set(ES_INJECTOR_SRC
    inject.cpp
)

set(ES_INJECTOR_HDR_STANDALONE
    es-injector.h
)

set(ES_INJECTOR_HDR)
foreach(HDR ${ES_INJECTOR_HDR_STANDALONE})
    set(HDR "${CMAKE_CURRENT_SOURCE_DIR}/../include/es-injector/${HDR}")
    list(APPEND ES_INJECTOR_HDR ${HDR})
endforeach()

foreach(SRC ${ES_INJECTOR_SRC})
    get_filename_component(HDR_NAME ${SRC} NAME_WLE)
    set(HDR "${CMAKE_CURRENT_SOURCE_DIR}/../include/es-injector/${HDR_NAME}.h")
    if(EXISTS ${HDR})
        list(APPEND ES_INJECTOR_HDR ${HDR})
    endif()
endforeach()

set(ES_INJECTOR_PUBLIC_LIBS
)

set(ES_INJECTOR_PRIVATE_LIBS
    fmt
    bsm
    EndpointSecurity
)

# ES_INJECTOR_HDR added for Xcode project generation
add_library(es-injector STATIC ${ES_INJECTOR_SRC} ${ES_INJECTOR_HDR})
set_target_properties(es-injector PROPERTIES PUBLIC_HEADER "${ES_INJECTOR_HDR}")

target_link_libraries(es-injector
PUBLIC
    ${ES_INJECTOR_PUBLIC_LIBS}
PRIVATE
    ${ES_INJECTOR_PRIVATE_LIBS}
)
target_compile_options(es-injector PRIVATE -Wall -Wextra -Wpedantic)

target_include_directories(es-injector
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

install(TARGETS es-injector
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include/es-injector
)
