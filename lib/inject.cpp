#include <es-injector/es-injector.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <cassert>
#include <dispatch/dispatch.h>
#include <set>

#include <fmt/format.h>
#include <frida-gum.h>

void es_cb(es_client_t *client, const es_message_t *message,
           const std::vector<std::string> &injected_env_vars,
           const std::set<std::string> &target_executables) {
    switch (message->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
        const auto name = std::string(message->event.exec.target->executable->path.data);
        fmt::print("name: {:s}\n", name);
        if (target_executables.contains(name)) {
            fmt::print("found target\n");
        }
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        break;
    }
    default:
        assert(!"unhandled type");
    }
}

void run_injector(const std::vector<std::string> &injected_env_vars,
                  const std::vector<std::string> &target_executables) {
    std::set<std::string> exes(target_executables.cbegin(), target_executables.cend());
    es_client_t *client = nullptr;
    auto new_client_res =
        es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
            es_cb(client, message, injected_env_vars, exes);
        });
    assert(client && new_client_res == ES_NEW_CLIENT_RESULT_SUCCESS);
    es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
    auto subscribe_res       = es_subscribe(client, events, sizeof(events) / sizeof(*events));
    assert(subscribe_res == ES_RETURN_SUCCESS);
    dispatch_main();
}
