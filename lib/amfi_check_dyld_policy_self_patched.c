// clang-format off
// clang -fomit-frame-pointer -Oz -c -o patched-x64.o -arch x86_64 lib/amfi_check_dyld_policy_self_patched.c
// clang -fomit-frame-pointer -Oz -c -o patched-arm64.o -arch arm64 lib/amfi_check_dyld_policy_self_patched.c
// clang-format on
#include <stdint.h>

int amfi_check_dyld_policy_self_patched(uint64_t input_flags, uint64_t *output_flags) {
    *output_flags = UINT64_MAX;
    return 0;
}
