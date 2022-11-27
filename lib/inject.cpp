#include <es-injector/es-injector.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <cassert>
#include <cstdint>
#include <dispatch/dispatch.h>
#include <filesystem>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <set>
#include <span>

#include <fmt/format.h>

constexpr uint32_t PAGE_SZ = 4096;

struct image_info {
    uint64_t base;
    uint64_t size;
    uint64_t slide;
    std::filesystem::path path;
    uint8_t uuid[16];
};

static void mach_check(kern_return_t kr, const std::string &msg) {
    if (kr != KERN_SUCCESS) {
        fmt::print(stderr, "Mach error: '{:s}' retval: {:d} description: '{:s}'\n", msg, kr,
                   mach_error_string(kr));
        exit(-1);
    }
}

// behavior:
// roundup_pow2_mul(16, 16) = 16
// roundup_pow2_mul(17, 16) = 32
template <typename U> static constexpr U roundup_pow2_mul(U num, size_t pow2_mul) {
    const U mask = static_cast<U>(pow2_mul) - 1;
    return (num + mask) & ~mask;
}

static std::vector<uint8_t> read_target(task_t target_task, uint64_t target_addr, uint64_t sz) {
    std::vector<uint8_t> res;
    res.resize(sz);
    vm_size_t vm_sz = sz;
    const auto kr   = vm_read_overwrite(target_task, (vm_address_t)target_addr, sz,
                                        (vm_address_t)res.data(), &vm_sz);
    mach_check(kr, "vm_read_overwrite");
    assert(vm_sz == sz);
    return res;
}

std::string read_cstr_target(task_t target_task, uint64_t target_addr) {
    std::vector<uint8_t> buf;
    do {
        const auto end_addr =
            target_addr % PAGE_SZ ? roundup_pow2_mul(target_addr, PAGE_SZ) : target_addr + PAGE_SZ;
        const auto smol_buf = read_target(target_task, target_addr, end_addr - target_addr);
        buf.insert(buf.end(), smol_buf.cbegin(), smol_buf.cend());
        target_addr = end_addr;
    } while (std::find(buf.cbegin(), buf.cend(), '\0') == buf.cend());
    return {(char *)buf.data()};
}

std::vector<image_info> get_dyld_image_infos(task_t target_task) {
    std::vector<image_info> res;
    task_dyld_info_data_t dyld_info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    mach_check(task_info(target_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt),
               "task_info dyld info");
    assert(dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64);
    const auto all_info_buf =
        read_target(target_task, dyld_info.all_image_info_addr, dyld_info.all_image_info_size);
    const dyld_all_image_infos *all_img_infos = (dyld_all_image_infos *)all_info_buf.data();

    if (!all_img_infos->infoArray) {
        return res;
    }

    const auto dyld_base       = (uint64_t)all_img_infos->dyldImageLoadAddress;
    const auto dyld_macho_segs = read_macho_segs_target(target_task, dyld_base);

    res.emplace_back(image_info{.base   = dyld_base,
                                .size   = get_text_size(dyld_macho_segs),
                                .slide  = dyld_base - get_text_base(dyld_macho_segs),
                                .path   = read_cstr_target(target_task, all_img_infos->dyldPath),
                                .uuid   = {},
                                .is_jit = false});

    const auto infos_buf = read_target(target_task, all_img_infos->infoArray,
                                       all_img_infos->infoArrayCount * sizeof(dyld_image_info));
    const auto img_infos = std::span<const dyld_image_info>{(dyld_image_info *)infos_buf.data(),
                                                            all_img_infos->infoArrayCount};
    for (const auto &img_info : img_infos) {
        const auto img_base   = (uint64_t)img_info.imageLoadAddress;
        const auto macho_segs = read_macho_segs_target(target_task, img_base);
        res.emplace_back(image_info{.base   = img_base,
                                    .size   = get_text_size(macho_segs),
                                    .slide  = img_base - get_text_base(macho_segs),
                                    .path   = read_cstr_target(target_task, img_info.imageFilePath),
                                    .uuid   = {},
                                    .is_jit = false});
    }

    std::sort(res.begin(), res.end());

    return res;
}

static void inject_stack(const task_t task, const std::vector<std::string> &injected_env_vars) {}

static void patch_dyld(const task_t task) {
    sym_finder_ctx ctx{};
    gum_darwin_enumerate_symbols(task, nullptr, sym_cb, (gpointer)&ctx);
    fmt::print("amfi_check_dyld_policy_self: {:p}\n", (void *)ctx.amfi_check_dyld_policy_self_addr);
}

static void inject(const audit_token_t token, const std::vector<std::string> &injected_env_vars) {
    const auto pid = audit_token_to_pid(token);
    assert(pid);
    task_t task = MACH_PORT_NULL;
    mach_check(task_for_pid(mach_task_self(), pid, &task), "tfp");
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
