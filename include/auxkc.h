#pragma once
#include <stddef.h>
#include <stdint.h>

#include "linker.h"

// the collection header page, the kexts are linked from here up
#define AUXKC_HEADER_SIZE 0x4000ULL

// build an auxiliary KC from kexts already linked at AUXKC_HEADER_SIZE and up
int auxkc_assemble(LinkedKext *kexts, size_t n, uint64_t boot_base,
                   const uint8_t boot_uuid[16], const uint8_t aux_uuid[16],
                   uint8_t **out_data, size_t *out_size);

// collection ids: feed every input through kc_uuid_hash, then kc_uuid_finish
void kc_uuid_hash(const void *data, size_t len, uint8_t io_uuid[16]);
void kc_uuid_finish(uint8_t uuid[16]);
