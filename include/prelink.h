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

// Assemble an MH_FILESET kernel collection (KC). See src/fileset.c.
int fileset_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size);
