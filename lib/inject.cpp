#include <es-injector/es-injector.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <cassert>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <set>

#include <fmt/format.h>
#include <frida-gum.h>

extern "C" GUM_API void gum_darwin_enumerate_symbols(mach_port_t task, const gchar *module_name,
                                                     GumFoundSymbolFunc func, gpointer user_data);

__attribute__((constructor)) void inject_init() {
    gum_init_embedded();
}

__attribute__((destructor)) void inject_fini() {
    gum_deinit_embedded();
}

static void inject_stack(const task_t task, const std::vector<std::string> &injected_env_vars) {}

struct sym_finder_ctx {
    uint64_t amfi_check_dyld_policy_self_addr;
};

static gboolean sym_cb(const GumSymbolDetails *details, gpointer user_data) {
    auto ctx = (sym_finder_ctx *)user_data;
    if (std::string(details->name) == "_amfi_check_dyld_policy_self") {
        ctx->amfi_check_dyld_policy_self_addr = details->address;
        return FALSE;
    }
    return TRUE;
}

static void patch_dyld(const task_t task) {
    sym_finder_ctx ctx{};
    gum_darwin_enumerate_symbols(task, nullptr, sym_cb, (gpointer)&ctx);
    fmt::print("amfi_check_dyld_policy_self: {:p}\n", (void *)ctx.amfi_check_dyld_policy_self_addr);
}

static void inject(const audit_token_t token, const std::vector<std::string> &injected_env_vars) {
    const auto pid = audit_token_to_pid(token);
    assert(pid);
    task_t task       = MACH_PORT_NULL;
    const auto kr_tfp = task_for_pid(mach_task_self(), pid, &task);
    assert(kr_tfp == KERN_SUCCESS);
    patch_dyld(task);
    inject_stack(task, injected_env_vars);
}

static void es_cb(es_client_t *client, const es_message_t *message,
                  const std::vector<std::string> &injected_env_vars,
                  const std::set<std::string> &target_executables) {
    switch (message->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
        const auto path = std::string(message->event.exec.target->executable->path.data);
        if (target_executables.contains(path)) {
            fmt::print("found target\n");
            inject(message->process->audit_token, injected_env_vars);
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
