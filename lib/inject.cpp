#include <es-injector/es-injector.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#undef NDEBUG
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <sys/ptrace.h>
#include <sys/syslimits.h>
#include <tuple>
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

#include <BS_thread_pool.hpp>
#include <fmt/format.h>

using namespace std::string_literals;
namespace fs = std::filesystem;

constexpr uint32_t PAGE_SZ_4K  = 4096;
constexpr uint32_t PAGE_SZ_16K = 16 * 1024;

template <> struct fmt::formatter<fs::path> {
    template <typename ParseContext> constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }
    template <typename FormatContext> auto format(const fs::path &path, FormatContext &ctx) {
        return fmt::format_to(ctx.out(), "{:s}", path.string());
    }
};

static void mach_check(kern_return_t kr, const std::string &msg) {
    if (kr != KERN_SUCCESS) {
        fmt::print(stderr, "Mach error: '{:s}' retval: {:d} description: '{:s}'\n", msg, kr,
                   mach_error_string(kr));
        exit(-1);
    }
}

static void checked_system(const std::vector<std::string> &argv) {
    const auto cmd = fmt::format("{}", fmt::join(argv, " "));
    fmt::print("cmd: {:s}\n", cmd);
    const auto res = system(cmd.c_str());
    assert(!res);
}

// https://gist.github.com/ccbrown/9722406
__attribute__((unused)) static void hexdump(const void *data, size_t size) {
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
    // hexdump(buf.data(), buf.size());
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

// static std::tuple<FILE *, fs::path> get_tmpfile(const std::string &prefix,
//                                                 const std::string &ext = "") {
static std::tuple<FILE *, fs::path> get_tmpfile(const std::string &prefix, const char *mode) {
    const auto tmp_path = fmt::format("/tmp/{:s}.XXXXXX", prefix);
    const auto fd       = mkstemp((char *)tmp_path.c_str());
    assert(fd >= 0);
    auto fh = fdopen(fd, mode);
    assert(fh);
    assert(!fchmod(fd, 1053 /* 0o555 */));
    return {fh, fs::path(tmp_path)};
}

static fs::path make_patch_dylib(const std::vector<uint8_t> &buf) {
    const auto [bin_fh, bin_path] = get_tmpfile("patch_dyld_bin", "wb");
    assert(fwrite(buf.data(), buf.size(), 1, bin_fh) == 1);
    assert(!fflush(bin_fh));
    const auto [asm_fh, asm_path] = get_tmpfile("patch_dyld_asm", "w");
    const auto asm_str            = fmt::format(R"(
.section __TEXT,__text
.align 14
.global _patched_dyld_amfi_page
_patched_dyld_amfi_page:
    .incbin "{:s}"
)",
                                                bin_path.string());
    fmt::print(asm_fh, "{:s}", asm_str);
    fmt::print("asm:\n{:s}\n", asm_str);
    fmt::print("asm_path: {}\n", asm_path);
    assert(!fflush(asm_fh));
    const auto [dylib_fh, dylib_path] = get_tmpfile("patch_dyld_dylib", "wb");
    (void)dylib_fh;
    checked_system({
        "clang",
        "-arch",
#ifdef __arm64__
#ifndef __arm64e__
        "arm64",
#else
        "arm64e",
#endif
#elif defined(__x86_64__)
        "x86_64",
#else
#error bad arch
#endif
        "-x",
        "assembler-with-cpp",
        "-shared",
        "-o",
        dylib_path.string(),
        asm_path.string(),
    });
    // fclose(asm_fh);
    return dylib_path;
}

static void remap_patch_dylib(const task_t task, const uint64_t patch_page_addr,
                              const fs::path &dylib_path) {
    const auto dylib_handle = dlopen(dylib_path.string().c_str(), RTLD_NOW | RTLD_GLOBAL);
    assert(dylib_handle);
    const auto our_patch_page_ptr = dlsym(dylib_handle, "patched_dyld_amfi_page");
    assert(our_patch_page_ptr);
#if !__has_feature(ptrauth_calls)
    const auto our_patch_page_addr = (uint64_t)our_patch_page_ptr;
#else
    const auto our_patch_page_addr =
        (uint64_t)ptrauth_strip(our_patch_page_ptr, ptrauth_key_process_independent_code);
#endif
    fmt::print("patch_page_addr: {:p}\n", (void *)patch_page_addr);
    fmt::print("our_patch_page_addr: {:p}\n", (void *)our_patch_page_addr);
    const auto kr_dealloc = vm_deallocate(task, patch_page_addr, PAGE_SZ_16K);
    mach_check(kr_dealloc, "vm_deallocate remap");
    vm_prot_t cur_prot         = VM_PROT_NONE;
    vm_prot_t max_prot         = VM_PROT_NONE;
    vm_address_t remapped_addr = patch_page_addr;
    const auto kr_remap =
        vm_remap(task, &remapped_addr, PAGE_SZ_16K, 0, VM_FLAGS_RETURN_DATA_ADDR, mach_task_self(),
                 (vm_address_t)our_patch_page_addr, false, &cur_prot, &max_prot, VM_INHERIT_NONE);
    fmt::print("remapped_addr: {:p} cur_prot: {:#0x} max_prot: {:#0x}\n", (void *)remapped_addr,
               cur_prot, max_prot);
    mach_check(kr_remap, "vm_remap");
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
    mach_check(kr_thread_get_gpr, "thread_get_state get_sp");
    arm_thread_state64_t our_gpr_state;
    mach_msg_type_number_t our_gpr_cnt = ARM_THREAD_STATE64_COUNT;
    const auto kr_convert_to_self      = thread_convert_thread_state(
        thread, THREAD_CONVERT_THREAD_STATE_TO_SELF, ARM_THREAD_STATE64, (thread_state_t)&gpr_state,
        gpr_cnt, (thread_state_t)&our_gpr_state, &our_gpr_cnt);
    mach_check(kr_convert_to_self, "thread_convert_thread_state to self get_sp");
    return arm_thread_state64_get_sp(our_gpr_state);
#elif defined(__x86_64__)
    mach_msg_type_number_t gpr_cnt = x86_THREAD_STATE64_COUNT;
    x86_thread_state64_t gpr_state;
    const auto kr_thread_get_gpr =
        thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&gpr_state, &gpr_cnt);
    mach_check(kr_thread_get_gpr, "thread_get_state get_sp");
    return gpr_state.__rsp;
#else
#error bad arch
#endif
}

__attribute__((noinline)) static void set_sp(const thread_t thread, uint64_t sp) {
#ifdef __arm64__
    mach_msg_type_number_t gpr_cnt = ARM_THREAD_STATE64_COUNT;
    arm_thread_state64_t gpr_state;
    const auto kr_thread_get_gpr =
        thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&gpr_state, &gpr_cnt);
    mach_check(kr_thread_get_gpr, "thread_get_state set_sp");
    arm_thread_state64_t our_gpr_state;
    mach_msg_type_number_t our_gpr_cnt = ARM_THREAD_STATE64_COUNT;
    const auto kr_convert_to_self      = thread_convert_thread_state(
        thread, THREAD_CONVERT_THREAD_STATE_TO_SELF, ARM_THREAD_STATE64, (thread_state_t)&gpr_state,
        gpr_cnt, (thread_state_t)&our_gpr_state, &our_gpr_cnt);
    mach_check(kr_convert_to_self, "thread_convert_thread_state to self set_sp");
    arm_thread_state64_set_sp(our_gpr_state, sp);
#if !__has_feature(ptrauth_calls)
    // gpr_state.__sp = sp;
#else
    // gpr_state.__opaque_sp = (void *)sp;
#endif
    arm_thread_state64_t their_gpr_state;
    mach_msg_type_number_t their_gpr_cnt = ARM_THREAD_STATE64_COUNT;
    const auto kr_convert_from_self =
        thread_convert_thread_state(thread, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
                                    ARM_THREAD_STATE64, (thread_state_t)&our_gpr_state, our_gpr_cnt,
                                    (thread_state_t)&their_gpr_state, &their_gpr_cnt);
    mach_check(kr_convert_from_self, "thread_convert_thread_state from self set_sp");
    const auto kr_thread_set_gpr = thread_set_state(
        thread, ARM_THREAD_STATE64, (thread_state_t)&their_gpr_state, their_gpr_cnt);
    mach_check(kr_thread_set_gpr, "thread_set_state set_sp");
#elif defined(__x86_64__)
    mach_msg_type_number_t gpr_cnt = x86_THREAD_STATE64_COUNT;
    x86_thread_state64_t gpr_state;
    const auto kr_thread_get_gpr =
        thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&gpr_state, &gpr_cnt);
    mach_check(kr_thread_get_gpr, "thread_get_state set_sp");
    gpr_state.__rsp = sp;
    const auto kr_thread_set_gpr = thread_set_state(
        thread, x86_THREAD_STATE64, (thread_state_t)&gpr_state, x86_THREAD_STATE64_COUNT);
    mach_check(kr_thread_set_gpr, "thread_set_state set_sp");
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

static std::pair<std::string, std::string> split_var(const std::string var_val) {
    const auto delim = var_val.find('=');
    assert(delim != std::string::npos);
    const auto var = var_val.substr(0, delim);
    const auto val = var_val.substr(delim + 1);
    return std::make_pair(var, val);
}

static std::string cat_var(const std::pair<std::string, std::string> &var_val) {
    return var_val.first + "=" + var_val.second;
}

static void dump_args(int argc, const char **argv, const char **envp, const char **apple) {
    int i;
    fmt::print("> argc: {:d}\n", argc);
    for (i = 0; i < argc; ++i) {
        fmt::print("> argv[{:d}] = {:s}\n", i, argv[i]);
    }
    i = 0;
    for (const char **p = envp; p != nullptr; ++p, ++i) {
        fmt::print("> envp[{:d}] = {:s}\n", i, *p);
    }
    i = 0;
    for (const char **p = apple; p != nullptr; ++p, ++i) {
        fmt::print("> apple[{:d}] = {:s}\n", i, *p);
    }
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
                            const std::vector<std::string> &injected_env_vars, const bool dump) {
    std::vector<std::string> args;
    std::map<std::string, std::string> env_vars;
    std::map<std::string, std::string> apple_vars;
    uint64_t max_stack_addr = 0;

#define DUMP(expr)                                                                                 \
    do {                                                                                           \
        if (dump) {                                                                                \
            expr;                                                                                  \
        }                                                                                          \
    } while (0)
#define SP_MAX(expr)                                                                               \
    do {                                                                                           \
        max_stack_addr = std::max(max_stack_addr, (expr));                                         \
    } while (0)

    const auto sp = get_sp(thread);
    fmt::print("old sp: {:p}\n", (void *)sp);
    SP_MAX(sp);

    const auto unk_addr = sp;
    const auto unk      = read_target<uint64_t>(task, unk_addr);
    DUMP(fmt::print("unk: {:#0x}\n", unk));

    const auto argc_addr = sp + sizeof(uint64_t);
    const auto argc      = read_target<int32_t>(task, argc_addr);
    DUMP(fmt::print("argc: {:d}\n", argc));
    SP_MAX(argc_addr);

    const auto argv_addr = argc_addr + sizeof(int64_t);
    SP_MAX(argv_addr);
    // +1 for NULL terminator
    const auto argv_buf = read_target(task, argv_addr, (argc + 1) * sizeof(const char *));
    SP_MAX(argv_addr + (argc + 1) * sizeof(const char *));
    const auto argv_addrs = (uint64_t *)argv_buf.data();
    for (int32_t i = 0; i < argc; ++i) {
        SP_MAX(argv_addrs[i]);
        const auto arg_val = read_cstr_target(task, argv_addrs[i]);
        SP_MAX(argv_addrs[i] + arg_val.size() + 1);
        DUMP(fmt::print("argv[{:d}] = {:s}\n", i, arg_val));
        args.emplace_back(arg_val);
    }

    const auto envp_addr = argv_addr + (argc + 1) * sizeof(const char *);
    SP_MAX(envp_addr);
    int envc = -1;
    for (int i = 0; true; ++i) {
        const auto envp_ptr = read_target<uint64_t>(task, envp_addr + i * sizeof(uint64_t));
        SP_MAX(envp_ptr);
        if (envp_ptr == 0) {
            envc = i;
            break;
        }
        const auto env_var = read_cstr_target(task, envp_ptr);
        SP_MAX(envp_ptr + env_var.size() + 1);
        DUMP(fmt::print("envp[{:d}] = {:s}\n", i, env_var));
        env_vars.emplace(split_var(env_var));
    }
    assert(envc >= 0);

    const auto apple_addr = envp_addr + (envc + 1) * sizeof(const char *);
    SP_MAX(apple_addr);
    int applec = -1;
    for (int i = 0; true; ++i) {
        const auto apple_ptr = read_target<uint64_t>(task, apple_addr + i * sizeof(uint64_t));
        SP_MAX(apple_ptr);
        if (apple_ptr == 0) {
            applec = i;
            break;
        }
        const auto apple_var = read_cstr_target(task, apple_ptr);
        SP_MAX(apple_ptr + apple_var.size() + 1);
        DUMP(fmt::print("apple[{:d}] = {:s}\n", i, apple_var));
        apple_vars.emplace(split_var(apple_var));
    }

    const auto max_stack_addr_aligned = roundup_pow2_mul(max_stack_addr, sizeof(uint64_t));

    const auto main_stack_pair = apple_vars.find("main_stack");
    assert(main_stack_pair != apple_vars.cend());
    const auto main_stack_val = main_stack_pair->second;
    const auto stack_delim    = main_stack_val.find(',');
    assert(stack_delim != std::string::npos);
    const auto stack_addr_str = main_stack_val.substr(0, stack_delim);
    const auto stack_addr     = strtoull(stack_addr_str.c_str(), nullptr, 16);
    assert(stack_addr == max_stack_addr_aligned);
    DUMP(fmt::print("stack_addr: {:p}\n", (void *)stack_addr));

    for (const auto &env_var : injected_env_vars) {
        auto p              = split_var(env_var);
        const auto r        = env_vars.insert_or_assign(p.first, p.second);
        const auto override = !r.second;
        DUMP(fmt::print("{:s} {:s} = {:s}\n", override ? "overriding" : "inserting", p.first,
                        p.second));
        if (!override) {
            ++envc;
        }
    }

    assert(env_vars.size() == envc);
    assert(apple_vars.size() == applec);
    const auto num_ptrs     = 2 + argc + envc + applec + 3;
    const auto num_pad_ptrs = num_ptrs % 2 ? 1 : 0;
    auto ptr_buf            = std::vector<uint8_t>((num_ptrs + num_pad_ptrs) * sizeof(uint64_t));
    auto ptrs               = (uint64_t *)ptr_buf.data();
    auto ptr                = ptrs;
    std::string strs;
    const auto exe_path_var_val = apple_vars.find("executable_path");
    assert(exe_path_var_val != apple_vars.cend());
    strs += cat_var(*exe_path_var_val) + "\0"s;
    apple_vars.erase(exe_path_var_val);

    *(uint64_t *)ptr = unk;
    ++ptr;

    *(int64_t *)ptr = argc;
    ++ptr;

    for (const auto &arg_val : args) {
        const auto str_idx = strs.size();
        *ptr               = str_idx;
        ++ptr;
        strs += arg_val + "\0"s;
    }
    *ptr = UINT64_MAX;
    ++ptr;
    for (const auto &env_var_val : env_vars) {
        const auto str_idx = strs.size();
        *ptr               = str_idx;
        ++ptr;
        strs += cat_var(env_var_val) + "\0"s;
    }
    *ptr = UINT64_MAX;
    ++ptr;
    *ptr = 0; // executable_path
    ++ptr;
    for (const auto &apple_var_val : apple_vars) {
        const auto str_idx = strs.size();
        *ptr               = str_idx;
        ++ptr;
        strs += cat_var(apple_var_val) + "\0"s;
    }
    *ptr = UINT64_MAX;
    ++ptr;
    while ((uint64_t)ptr % 16) {
        ++ptr;
    }
    fmt::print("ptr: {:p} end: {:p}\n", fmt::ptr(ptr), fmt::ptr(ptr_buf.data() + ptr_buf.size()));
    assert(ptr_buf.data() + ptr_buf.size() == (uint8_t *)ptr);
    while (strs.size() % 16 != 0) {
        strs += "\0"s;
    }
    const auto strs_addr = stack_addr - strs.size();
    write_target(task, strs_addr, std::span<uint8_t>((uint8_t *)strs.data(), strs.size()));

    for (int i = 2; i < num_ptrs; ++i) {
        if (ptrs[i] == UINT64_MAX) {
            ptrs[i] = 0;
        } else {
            ptrs[i] += strs_addr;
        }
    }
    const auto ptrs_addr = strs_addr - ptr_buf.size();
    fmt::print("ptrs_addr = {:p} ptr_buf.size(): {:#0x} ptr_buf end: {:p}\n", (void *)ptrs_addr,
               ptr_buf.size(), (void *)(ptrs_addr + ptr_buf.size() + strs.size()));

    write_target(task, ptrs_addr, std::span<uint8_t>(ptr_buf.data(), ptr_buf.size()));
    fmt::print("new sp: {:p}\n", (void *)ptrs_addr);
    // dump_args()
    set_sp(thread, ptrs_addr);
#undef DUMP
}

__attribute__((used)) int dummy_var;

static bool patch_dyld(const task_t task) {
    const auto dyld_base = get_dyld_base(task);
    fmt::print("dyld_base: {:p}\n", (void *)dyld_base);
    const auto arm64 = is_arm64(task, dyld_base);
#ifdef __arm64__
    // assert(arm64);
    if (!arm64) {
        fmt::print("arm64 wrong arm64: {:b}\n", arm64);
        return false;
    }
#else
    // assert(!arm64);
    if (arm64) {
        fmt::print("x86_64 wrong arm64: {:b}\n", arm64);
        return false;
    }
#endif
    const auto amfi_check_dyld_policy_self_addr =
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
    // brk #1
    const uint8_t breakpoint[] = {0x20, 0x00, 0x20, 0xd4};
    // nop
    const uint8_t nop[] = {0x1f, 0x20, 0x03, 0xd5};
#elif defined(__x86_64__)
    // or qword ptr [rsi], -1
    // xor eax, eax
    // ret
    const uint8_t patch[] = {0x48, 0x83, 0x0e, 0xff, 0x31, 0xc0, 0xc3};
    // ud2
    const uint8_t breakpoint[] = {0x0f, 0x0b};
    // nop
    const uint8_t nop[] = {0x90};
#else
#error bad arch
#endif

    const auto patch_page_addr = rounddown_pow2_mul(amfi_check_dyld_policy_self_addr, PAGE_SZ_16K);
    auto patch_page_buf        = read_target(task, patch_page_addr, PAGE_SZ_16K);
    if (true) {
        const auto patch_page_off = amfi_check_dyld_policy_self_addr - patch_page_addr;
        std::copy(patch, patch + sizeof(patch), patch_page_buf.data() + patch_page_off);
        if (false) {
            std::copy(breakpoint, breakpoint + sizeof(breakpoint),
                      patch_page_buf.data() + patch_page_off);
        }
    } else {
        for (unsigned int off = 0; off < patch_page_buf.size() - sizeof(breakpoint);
             off += sizeof(nop)) {
            std::copy(nop, nop + sizeof(nop), patch_page_buf.data() + off);
        }
        std::copy(breakpoint, breakpoint + sizeof(breakpoint),
                  patch_page_buf.data() + patch_page_buf.size() - sizeof(breakpoint));
    }
    const auto patch_dylib_path = make_patch_dylib(patch_page_buf);
    remap_patch_dylib(task, patch_page_addr, patch_dylib_path);
    return true;

    if (false) {
        const auto kr_prot_rw = vm_protect(task, patch_page_addr, PAGE_SZ_4K, 0,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        mach_check(kr_prot_rw, "vm_protect RW");
        write_target(task, amfi_check_dyld_policy_self_addr,
                     std::span<const uint8_t>(patch, sizeof(patch)));
        const auto kr_prot_rx =
            vm_protect(task, patch_page_addr, PAGE_SZ_4K, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        mach_check(kr_prot_rx, "vm_protect RX");
        return true;
    }
}

static bool inject(es_client_t *client, const es_message_t *message,
                   const std::vector<std::string> &injected_env_vars, const bool dump) {
    const auto pid = audit_token_to_pid(message->process->audit_token);
    assert(pid);
    fmt::print("injecting pid: {:d}\n", pid);
    // assert(!ptrace(PT_ATTACHEXC, pid, nullptr, 0));
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
    const auto patch_ok = patch_dyld(task);
    // const auto patch_ok = true;
    if (!patch_ok) {
        fmt::print("patch failed\n");
        return false;
    }
    fmt::print("injecting env vars\n");
    inject_env_vars(task, thread, injected_env_vars, dump);
    fmt::print("injecting env vars done\n");
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    return true;
}

static void es_cb(es_client_t *client, const es_message_t *message,
                  const std::vector<std::string> &injected_env_vars,
                  const std::set<std::string> &target_executables, BS::thread_pool *thread_pool,
                  bool dump) {
    switch (message->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
        const auto path = std::string(message->event.exec.target->executable->path.data);
        if (target_executables.contains(path)) {
            std::filesystem::path p(path);
            fmt::print("found target: {:s}\n", p.filename().string());
            thread_pool->push_task(inject, client, message, injected_env_vars, dump);
        } else {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        }
        break;
    }
    default:
        assert(!"unhandled type");
    }
}

void run_injector(const std::vector<std::string> &injected_env_vars,
                  const std::vector<std::string> &target_executables, const bool dump) {
    std::set<std::string> exes(target_executables.cbegin(), target_executables.cend());
    es_client_t *client                          = nullptr;
    std::unique_ptr<BS::thread_pool> thread_pool = std::make_unique<BS::thread_pool>();
    const auto tp                                = thread_pool.get();
    auto new_client_res =
        es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
            es_cb(client, message, injected_env_vars, exes, tp, dump);
        });
    assert(client && new_client_res == ES_NEW_CLIENT_RESULT_SUCCESS);
    es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
    auto subscribe_res       = es_subscribe(client, events, sizeof(events) / sizeof(*events));
    assert(subscribe_res == ES_RETURN_SUCCESS);
    dispatch_main();
}
