#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
  char *name;
  uint64_t addr;
} Sym;

typedef struct {
  Sym *syms;
  size_t count;
  size_t cap;
} SymTable;

typedef struct {
  char bundle_id[256];
  char bundle_path[512];
  char version[64];
  uint8_t *linked_data;
  size_t linked_size;
  uint64_t load_vmaddr;
  uint64_t header_vmaddr;
  uint64_t kmod_info_addr;
  char *info_plist_xml;
  size_t info_plist_len;
  int codeless;   // 1 = codeless kext (Info.plist only, no executable/segments,
                  // e.g. com.apple.kpi.* KPI pseudo-kexts): emit a plist-only
                  // _PrelinkInfoDictionary entry so dependency resolution finds
                  // it, but place no code and add no LC_FILESET_ENTRY.
} LinkedKext;

typedef struct {
  uint64_t text_exec_cursor;
  uint64_t data_const_cursor;
  uint64_t data_cursor;
} KcPlacement;

int symtab_build_from_macho(SymTable *st, const uint8_t *data, size_t size);
int symtab_merge_from_linked(SymTable *st, const LinkedKext *lk);
void symtab_free(SymTable *st);
int patch_kmod_info(LinkedKext *lk);
uint64_t symtab_lookup(const SymTable *st, const char *name);

// Compute the highest VM address across all non-zero segments in a kernel Mach-O.
uint64_t macho_kernel_vm_end(const uint8_t *data, size_t size);

int macho_find_segment(const uint8_t *data, size_t size, const char *segname,
                       uint64_t *vmaddr, uint64_t *vmsize);

int link_kext(const uint8_t *kext_data, size_t kext_size,
              const SymTable *combined_syms, uint64_t load_vmaddr,
              LinkedKext *out);

int link_kext_placed(const uint8_t *kext_data, size_t kext_size,
                     const SymTable *combined_syms, uint64_t file_anchor_vmaddr,
                     KcPlacement *placement, LinkedKext *out);
