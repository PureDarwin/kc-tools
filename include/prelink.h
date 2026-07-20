#pragma once
#include "linker.h"
#include <stdint.h>
#include <stddef.h>

int prelink_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size);

int prelink_assemble_merged(const uint8_t *kernel_data, size_t kernel_size,
                            LinkedKext *kexts, size_t num_kexts,
                            uint8_t **out_data, size_t *out_size,
                            size_t *out_header_foffs);

// Grows the KC's own __TEXT_EXEC/__DATA_CONST/__DATA segments in place to
// contain kext content (arm64 fileset contract), leaving the kernel's own
// __PLK_TEXT_EXEC/__PLK_DATA_CONST/__PRELINK_DATA/__PRELINK_TEXT/
// __PRELINK_INFO placeholders untouched (still empty), per arm_vm_init.c's
// "kernel's own copy must be empty" asserts.
int prelink_assemble_kc(const uint8_t *kernel_data, size_t kernel_size,
                        LinkedKext *kexts, size_t num_kexts,
                        uint8_t **out_data, size_t *out_size,
                        size_t *out_header_foffs);

// Assemble an MH_FILESET kernel collection (KC). See src/fileset.c.
int fileset_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size);
