#include <es-injector/es-injector.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#undef NDEBUG
#include <cassert>
#include <cstdint>
#include <dispatch/dispatch.h>
#include <filesystem>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <set>
#include <span>

#include <fmt/format.h>

constexpr uint32_t PAGE_SZ_4K = 4096;

static void mach_check(kern_return_t kr, const std::string &msg) {
    if (kr != KERN_SUCCESS) {
        fmt::print(stderr, "Mach error: '{:s}' retval: {:d} description: '{:s}'\n", msg, kr,
                   mach_error_string(kr));
        exit(-1);
    }
}

// https://gist.github.com/ccbrown/9722406
static void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

// behavior:
// roundup_pow2_mul(16, 16) = 16
// roundup_pow2_mul(17, 16) = 32
template <typename U> static constexpr U roundup_pow2_mul(U num, size_t pow2_mul) {
    const U mask = static_cast<U>(pow2_mul) - 1;
    return (num + mask) & ~mask;
}

// behavior:
// roundup_pow2_mul(16, 16) = 16
// roundup_pow2_mul(17, 16) = 16
template <typename U> static constexpr U rounddown_pow2_mul(U num, size_t pow2_mul) {
    const U mask = static_cast<U>(pow2_mul) - 1;
    return num & ~mask;
}

static std::vector<uint8_t> read_target(const task_t task, uint64_t addr, uint64_t sz) {
    std::vector<uint8_t> res;
    res.resize(sz);
    vm_size_t vm_sz = sz;
    const auto kr =
        vm_read_overwrite(task, (vm_address_t)addr, sz, (vm_address_t)res.data(), &vm_sz);
    mach_check(kr, "vm_read_overwrite");
    assert(vm_sz == sz);
    return res;
}

template <typename T> static T read_target(const task_t task, uint64_t addr) {
    const auto buf = read_target(task, addr, sizeof(T));
    hexdump(buf.data(), buf.size());
    return *(T *)buf.data();
}

static void write_target(const task_t task, uint64_t addr, std::span<const uint8_t> buf) {
    const auto kr = vm_write(task, (vm_address_t)addr, (vm_offset_t)buf.data(),
                             (mach_msg_type_number_t)buf.size_bytes());
    mach_check(kr, "vm_write");
}

static std::string read_cstr_target(const task_t task, uint64_t addr) {
    std::vector<uint8_t> buf;
    do {
        const auto end_addr =
            addr % PAGE_SZ_4K ? roundup_pow2_mul(addr, PAGE_SZ_4K) : addr + PAGE_SZ_4K;
        const auto smol_buf = read_target(task, addr, end_addr - addr);
        buf.insert(buf.end(), smol_buf.cbegin(), smol_buf.cend());
        addr = end_addr;
    } while (std::find(buf.cbegin(), buf.cend(), '\0') == buf.cend());
    return {(char *)buf.data()};
}

static bool is_macho_magic_at(const task_t task, uint64_t addr) {
    const auto macho_magic_buf = read_target(task, addr, 4);
    return *(uint32_t *)macho_magic_buf.data() == MH_MAGIC_64;
}

static uint64_t get_dyld_base(const task_t task) {
    task_dyld_info_data_t dyld_info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    mach_check(task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt),
               "task_info dyld info");
    assert(dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64);
    const auto all_info_buf =
        read_target(task, dyld_info.all_image_info_addr, dyld_info.all_image_info_size);
    const dyld_all_image_infos *all_img_infos = (dyld_all_image_infos *)all_info_buf.data();
    assert(all_img_infos->version >= 10); // when amfi_check_dyld_policy_self was added
    // dyldImageLoadAddress isn't initialized at this early stage, scan down for macho header
    uint64_t macho_probe_addr = rounddown_pow2_mul(dyld_info.all_image_info_addr, PAGE_SZ_4K);
    while (!is_macho_magic_at(task, macho_probe_addr)) {
        macho_probe_addr -= PAGE_SZ_4K;
    }
    return macho_probe_addr;
}

static bool is_arm64(const task_t task, const uint64_t dyld_base) {
    const auto hdr_buf = read_target(task, dyld_base, sizeof(mach_header_64));
    const auto hdr     = (mach_header_64 *)hdr_buf.data();
    assert(hdr->magic == MH_MAGIC_64);
    assert(hdr->cputype == CPU_TYPE_X86_64 || hdr->cputype == CPU_TYPE_ARM64);
    return hdr->cputype == CPU_TYPE_ARM64;
}

static uint64_t get_sp(const thread_t thread) {
#ifdef __arm64__
    mach_msg_type_number_t gpr_cnt = ARM_THREAD_STATE64_COUNT;
    arm_thread_state64_t gpr_state;
    const auto kr_thread_get_gpr =
        thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&gpr_state, &gpr_cnt);
    mach_check(kr_thread_get_gpr, "thread_get_state sp");
    return arm_thread_state64_get_sp(gpr_state);
#elif defined(__x86_64__)
    mach_msg_type_number_t gpr_cnt = x86_THREAD_STATE64_COUNT;
    x86_thread_state64_t gpr_state;
    const auto kr_thread_get_gpr =
        thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&gpr_state, &gpr_cnt);
    mach_check(kr_thread_get_gpr, "thread_get_state sp");
    return gpr_state.__rsp;
#else
#error bad arch
#endif
}

static uint64_t get_amfi_check_dyld_policy_self_addr(const task_t task, const uint64_t dyld_base) {
    const auto hdr_buf = read_target(task, dyld_base, sizeof(mach_header_64));
    const auto hdr     = (mach_header_64 *)hdr_buf.data();
    assert(hdr->magic == MH_MAGIC_64);
    const auto cmd_buf   = read_target(task, dyld_base + sizeof(mach_header_64), hdr->sizeofcmds);
    const auto end_of_lc = (load_command *)(cmd_buf.data() + hdr->sizeofcmds);
    for (auto lc = (load_command *)cmd_buf.data(); lc < end_of_lc;
         lc      = (load_command *)((uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SYMTAB) {
            continue;
        }
        const auto symtab = (symtab_command *)lc;
        const auto symbuf =
            read_target(task, dyld_base + symtab->symoff, symtab->nsyms * sizeof(nlist_64));
        const auto syms   = (nlist_64 *)symbuf.data();
        const auto strbuf = read_target(task, dyld_base + symtab->stroff, symtab->strsize);
        const auto strs   = strbuf.data();
        for (uint32_t i = 0; i < symtab->nsyms; ++i) {
            const auto sym  = syms[i];
            const auto name = std::string((char *)&strs[sym.n_un.n_strx]);
            if (name == "_amfi_check_dyld_policy_self") {
                return dyld_base + sym.n_value;
            }
        }
        assert(!"amfi_check_dyld_policy_self not found");
    }
    assert(!"symtab not found");
}

/* bsd/kern/kern_exec.c: exec_copyout_strings
 *
 *      +-------------+ <- p->user_stack
 *      |     16b     |
 *      +-------------+
 *      | STRING AREA |
 *      |      :      |
 *      |      :      |
 *      |      :      |
 *      +- -- -- -- --+
 *      |  PATH AREA  |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      |  applev[n]  |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |  applev[1]  |
 *      +-------------+
 *      | exec_path / |
 *      |  applev[0]  |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      |    env[n]   |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |    env[0]   |
 *      +-------------+
 *      |      0      |
 *      +-------------+
 *      | arg[argc-1] |
 *      +-------------+
 *             :
 *             :
 *      +-------------+
 *      |    arg[0]   |
 *      +-------------+
 *      |     argc    |
 * sp-> +-------------+
 *
 */
static void inject_env_vars(const task_t task, const thread_t thread,
                            const std::vector<std::string> &injected_env_vars) {
    (void)injected_env_vars;
    const auto sp = get_sp(thread);
    fmt::print("sp: {:p}\n", (void *)sp);
    const auto argc = read_target<int32_t>(task, sp + sizeof(uint64_t));
    fmt::print("argc: {:d}\n", argc);
    const auto argv_addr = sp + 2 * sizeof(uint64_t);
    // +1 for NULL terminator
    const auto argv_buf   = read_target(task, argv_addr, (argc + 1) * sizeof(const char *));
    const auto argv_addrs = (uint64_t *)argv_buf.data();
    for (int32_t i = 0; i < argc; ++i) {
        fmt::print("&argv[{:d}] = {:p}\n", i, (void *)argv_addrs[i]);
        fmt::print("argv[{:d}] = {:s}\n", i, read_cstr_target(task, argv_addrs[i]));
    }
}

static void patch_dyld(const task_t task) {
    const auto dyld_base = get_dyld_base(task);
    fmt::print("dyld_base: {:p}\n", (void *)dyld_base);
    const auto arm64 = is_arm64(task, dyld_base);
#ifdef __arm64__
    assert(arm64);
#else
    assert(!arm64);
#endif
    uint64_t amfi_check_dyld_policy_self_addr =
        get_amfi_check_dyld_policy_self_addr(task, dyld_base);
    fmt::print("amfi_check_dyld_policy_self: {:p}\n", (void *)amfi_check_dyld_policy_self_addr);
    // int amfi_check_dyld_policy_self_patched(uint64_t inFlags, uint64_t* outFlags) {
    //     *outFlags = UINT64_MAX;
    //     return 0;
    // }
#ifdef __arm64__
    // mov x8, #-1
    // str x8, [x1]
    // mov w0, #0
    // ret
    const uint8_t patch[] = {0x08, 0x00, 0x80, 0x92, 0x28, 0x00, 0x00, 0xf9,
                             0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
#elif defined(__x86_64__)
    // or qword ptr [rsi], -1
    // xor eax, eax
    // ret
    const uint8_t patch[] = {0x48, 0x83, 0x0e, 0xff, 0x31, 0xc0, 0xc3};
#else
#error bad arch
#endif
    const auto patch_page_addr = rounddown_pow2_mul(amfi_check_dyld_policy_self_addr, PAGE_SZ_4K);
    const auto kr_prot_rw      = vm_protect(task, patch_page_addr, PAGE_SZ_4K, 0,
                                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    mach_check(kr_prot_rw, "vm_protect RW");
    write_target(task, amfi_check_dyld_policy_self_addr,
                 std::span<const uint8_t>(patch, sizeof(patch)));
    const auto kr_prot_rx =
        vm_protect(task, patch_page_addr, PAGE_SZ_4K, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    mach_check(kr_prot_rx, "vm_protect RX");
}

static void inject(const audit_token_t token, const std::vector<std::string> &injected_env_vars) {
    const auto pid = audit_token_to_pid(token);
    assert(pid);
    task_t task = MACH_PORT_NULL;
    mach_check(task_for_pid(mach_task_self(), pid, &task), "tfp");
    thread_act_array_t thread_list;
    mach_msg_type_number_t num_threads;
    const auto kr_threads = task_threads(task, &thread_list, &num_threads);
    mach_check(kr_threads, "task_threads");
    assert(num_threads == 1);
    thread_t thread       = thread_list[0];
    const auto kr_dealloc = vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                                          sizeof(thread_act_t) * num_threads);
    mach_check(kr_dealloc, "vm_deallocate");
    patch_dyld(task);
    inject_env_vars(task, thread, injected_env_vars);
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
