#include "linker.h"
#include "macho_fmt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

static uint32_t r32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t r64(const uint8_t *p) {
  return (uint64_t)r32(p) | ((uint64_t)r32(p + 4) << 32);
}

static void w32(uint8_t *p, uint32_t v) {
  p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static void w64(uint8_t *p, uint64_t v) {
  w32(p, (uint32_t)v); w32(p + 4, (uint32_t)(v >> 32));
}

static uint64_t read_uleb(const uint8_t **pp, const uint8_t *end) {
  uint64_t r = 0; int s = 0; const uint8_t *p = *pp;
  while (p < end) {
    uint8_t b = *p++;
    r |= (uint64_t)(b & 0x7f) << s;
    s += 7;
    if (!(b & 0x80))
      break;
  }
  *pp = p;
  return r;
}

static int64_t read_sleb(const uint8_t **pp, const uint8_t *end) {
  int64_t r = 0; int s = 0; const uint8_t *p = *pp; uint8_t b = 0;
  while (p < end) {
    b = *p++;
    r |= (int64_t)(b & 0x7f) << s;
    s += 7;
    if (!(b & 0x80))
      break;
  }
  if (s < 64 && (b & 0x40))
    r |= -(int64_t)(1ULL << s);
  *pp = p;
  return r;
}

static int sym_cmp(const void *a, const void *b) {
  return strcmp(((Sym *)a)->name, ((Sym *)b)->name);
}

// LC_DYLD_INFO(_ONLY) command + payload (mach-o/loader.h). Defined here so this
// shared linker is self-contained across both trees' macho_fmt.h variants.
#ifndef LC_DYLD_INFO
#define LC_DYLD_INFO 0x22
#endif

#ifndef LC_DYLD_INFO_ONLY
#define LC_DYLD_INFO_ONLY (0x22 | 0x80000000)   // 0x22 | LC_REQ_DYLD
#endif

struct dyld_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
};

#define REBASE_OPCODE_MASK                              0xF0
#define REBASE_IMMEDIATE_MASK                           0x0F
#define REBASE_OPCODE_DONE                              0x00
#define REBASE_OPCODE_SET_TYPE_IMM                      0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB       0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB                     0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED               0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES               0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES              0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB           0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define BIND_OPCODE_MASK                                0xF0
#define BIND_IMMEDIATE_MASK                             0x0F
#define BIND_OPCODE_DONE                                0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM               0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB              0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM               0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM       0x40
#define BIND_OPCODE_SET_TYPE_IMM                        0x50
#define BIND_OPCODE_SET_ADDEND_SLEB                     0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB         0x70
#define BIND_OPCODE_ADD_ADDR_ULEB                       0x80
#define BIND_OPCODE_DO_BIND                             0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB               0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED         0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB    0xC0

typedef struct { uint64_t fileoff; uint64_t vmaddr; uint64_t filesize; } SegInfo;

static void symtab_add(SymTable *st, const char *name, uint64_t addr) {
  if (st->count == st->cap) {
    st->cap = st->cap ? st->cap * 2 : 4096;
    st->syms = realloc(st->syms, st->cap * sizeof(Sym));
  }
  st->syms[st->count].name = strdup(name);
  st->syms[st->count].addr = addr;
  st->count++;
}

static const uint8_t *find_slice(const uint8_t *data, size_t size, size_t *out_sz) {
  if (size < 8)
    return NULL;
  uint32_t magic = r32(data);
  if (magic == MH_MAGIC_64) {
    *out_sz = size;
    return data;
  }

  if (magic == FAT_MAGIC) {
    uint32_t narch = (uint32_t)data[7] | ((uint32_t)data[6] << 8) |  ((uint32_t)data[5] << 16) | ((uint32_t)data[4] << 24);
    const uint8_t *fa = data + 8;
    for (uint32_t i = 0; i < narch && fa + 20 <= data + size; i++, fa += 20) {
      int32_t ct = (int32_t)((uint32_t)fa[0] << 24 | (uint32_t)fa[1] << 16 | (uint32_t)fa[2] << 8  | fa[3]);
      uint32_t off = (uint32_t)fa[8]  << 24 | (uint32_t)fa[9]  << 16 | (uint32_t)fa[10] << 8  | fa[11];
      uint32_t sz = (uint32_t)fa[12] << 24 | (uint32_t)fa[13] << 16 | (uint32_t)fa[14] << 8  | fa[15];
      if (ct == CPU_TYPE_X86_64 && off + sz <= size) {
        *out_sz = sz;
        return data + off;
      }
    }
  }

  return NULL;
}

int symtab_build_from_macho(SymTable *st, const uint8_t *data, size_t size) {
  size_t sl;
  const uint8_t *s = find_slice(data, size, &sl);
  if (!s) {
    fprintf(stderr, "symtab: not a 64-bit Mach-O\n");
    return -1;
  }

  const struct mach_header_64 *mh = (const struct mach_header_64 *)s;
  const struct symtab_command *sc = NULL;
  const uint8_t *lc = s + sizeof(*mh);
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    if (r32(lc) == LC_SYMTAB)
      sc = (const struct symtab_command *)lc;
    lc += r32(lc + 4);
  }

  if (!sc) {
    fprintf(stderr, "symtab: no LC_SYMTAB\n");
    return -1;
  }

  const struct nlist_64 *nl = (const struct nlist_64 *)(s + sc->symoff);
  const char *strtab = (const char *)(s + sc->stroff);
  for (uint32_t i = 0; i < sc->nsyms; i++) {
    const struct nlist_64 *n = &nl[i];
    if ((n->n_type & N_EXT) && (n->n_type & 0xe) == N_SECT && n->n_value)
      symtab_add(st, strtab + n->n_un.n_strx, n->n_value);
  }

  qsort(st->syms, st->count, sizeof(Sym), sym_cmp);
  fprintf(stderr, "symtab: %zu kernel symbols\n", st->count);

  return 0;
}

uint64_t macho_kernel_vm_end(const uint8_t *data, size_t size) {
  size_t sl;
  const uint8_t *s = find_slice(data, size, &sl);
  if (!s)
    return 0;

  const struct mach_header_64 *mh = (const struct mach_header_64 *)s;
  const uint8_t *lc = s + sizeof(*mh);
  uint64_t highest = 0;
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    uint32_t cmd = r32(lc), sz = r32(lc + 4);
    if (cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
      if (sc->vmsize > 0) {
        uint64_t end = sc->vmaddr + sc->vmsize;
        if (end > highest)
          highest = end;
      }
    }
    lc += sz;
  }

  return highest;
}

uint64_t macho_exec_vm_end(const uint8_t *data, size_t size) {
  size_t sl;
  const uint8_t *s = find_slice(data, size, &sl);
  if (!s)
    return 0;

  const struct mach_header_64 *mh = (const struct mach_header_64 *)s;
  const uint8_t *lc = s + sizeof(*mh);
  uint64_t highest = 0;
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    uint32_t cmd = r32(lc), sz = r32(lc + 4);
    if (cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc =
          (const struct segment_command_64 *)lc;
      if ((sc->initprot & VM_PROT_EXECUTE) != 0 && sc->vmsize > 0) {
        uint64_t end = sc->vmaddr + sc->vmsize;
        if (end > highest)
          highest = end;
      }
    }
    lc += sz;
  }
  return highest;
}

int symtab_merge_from_linked(SymTable *st, const LinkedKext *lk) {
  if (!st ||
    !lk ||
    !lk->linked_data ||
    lk->linked_size < sizeof(struct mach_header_64))
  {
    return 0;
  }

  const uint8_t *data = lk->linked_data;
  size_t size = lk->linked_size;

  const struct mach_header_64 *mh =
    (const struct mach_header_64 *)data;

  if (mh->magic != MH_MAGIC_64)
    return -1;

  const struct symtab_command *symcmd = NULL;
  const uint8_t *lcp = data + sizeof(*mh);

  for (uint32_t i = 0; i < mh->ncmds; i++) {
    size_t lc_offset = (size_t)(lcp - data);

    if (lc_offset > size ||
      size - lc_offset < sizeof(struct load_command)) {
      return -1;
    }

    uint32_t cmd = r32(lcp);
    uint32_t cmdsize = r32(lcp + 4);

    if (cmdsize < sizeof(struct load_command) ||
      cmdsize > size - lc_offset) {
      return -1;
    }

    if (cmd == LC_SYMTAB) {
      if (cmdsize < sizeof(struct symtab_command))
        return -1;

      symcmd =
        (const struct symtab_command *)lcp;
    }

    lcp += cmdsize;
  }

  if (!symcmd)
    return 0;

  uint64_t symbols_end =
    (uint64_t)symcmd->symoff +
    (uint64_t)symcmd->nsyms *
      sizeof(struct nlist_64);

  uint64_t strings_end =
    (uint64_t)symcmd->stroff +
    symcmd->strsize;

  if (symbols_end > size || strings_end > size)
    return -1;

  const struct nlist_64 *symbols =
    (const struct nlist_64 *)(data + symcmd->symoff);

  const char *string_table =
    (const char *)(data + symcmd->stroff);

  size_t added = 0;

  for (uint32_t i = 0; i < symcmd->nsyms; i++) {
    const struct nlist_64 *n = &symbols[i];

    if (!(n->n_type & N_EXT))
      continue;

    if ((n->n_type & N_TYPE) != N_SECT)
      continue;

    if (!n->n_value || n->n_sect == NO_SECT)
      continue;

    if (n->n_un.n_strx >= symcmd->strsize)
      continue;

    const char *name =
      string_table + n->n_un.n_strx;

    size_t remaining =
      symcmd->strsize - n->n_un.n_strx;

    if (!memchr(name, '\0', remaining))
      continue;

    /*
     * These belong to each individual kext and must never satisfy an
     * undefined reference from another kext.
     */
    if (!strcmp(name, "_kmod_info") ||
      !strcmp(name, "kmod_info") ||
      !strcmp(name, "__realmain") ||
      !strcmp(name, "__antimain") ||
      !strcmp(name, "__kext_apple_cc")) {
      continue;
    }

    symtab_add(st, name, n->n_value);
    added++;
  }

  if (added)
    qsort(st->syms,
        st->count,
        sizeof(Sym),
        sym_cmp);

  fprintf(stderr,
      " merged %zu symbols from %s\n",
      added,
      lk->bundle_id
        ? lk->bundle_id
        : "<unknown>");

  return 0;
}

void symtab_free(SymTable *st) {
  for (size_t i = 0; i < st->count; i++)
    free(st->syms[i].name);
  free(st->syms);
  memset(st, 0, sizeof(*st));
}

static uint64_t va_to_foff(
  const uint8_t *buf,
  size_t size,
  uint64_t va,
  size_t access_size)
{
  if (!buf || size < sizeof(struct mach_header_64))
    return UINT64_MAX;

  const struct mach_header_64 *mh =
    (const struct mach_header_64 *)buf;

  if (mh->magic != MH_MAGIC_64)
    return UINT64_MAX;

  const uint8_t *lcp = buf + sizeof(*mh);

  for (uint32_t i = 0; i < mh->ncmds; i++) {
    size_t lc_offset = (size_t)(lcp - buf);

    if (lc_offset > size ||
      size - lc_offset < sizeof(struct load_command)) {
      return UINT64_MAX;
    }

    uint32_t cmd = r32(lcp);
    uint32_t cmdsize = r32(lcp + 4);

    if (cmdsize < sizeof(struct load_command) ||
      cmdsize > size - lc_offset) {
      return UINT64_MAX;
    }

    if (cmd == LC_SEGMENT_64) {
      if (cmdsize < sizeof(struct segment_command_64))
        return UINT64_MAX;

      const struct segment_command_64 *seg =
        (const struct segment_command_64 *)lcp;

      size_t required =
        sizeof(*seg) +
        (size_t)seg->nsects * sizeof(struct section_64);

      if (required > cmdsize)
        return UINT64_MAX;

      const struct section_64 *sections =
        (const struct section_64 *)(seg + 1);

      /*
       * Prefer section mappings. Segment filesize does not necessarily
       * describe a simple VA-to-file mapping when a segment contains
       * gaps or zerofill sections.
       */
      for (uint32_t j = 0; j < seg->nsects; j++) {
        const struct section_64 *sec = &sections[j];
        uint32_t section_type = sec->flags & SECTION_TYPE;

        if (section_type == S_ZEROFILL
#ifdef S_GB_ZEROFILL
          || section_type == S_GB_ZEROFILL
#endif
#ifdef S_THREAD_LOCAL_ZEROFILL
          || section_type == S_THREAD_LOCAL_ZEROFILL
#endif
        ) {
          continue;
        }

        if (va < sec->addr)
          continue;

        uint64_t delta = va - sec->addr;

        if (delta > sec->size)
          continue;

        if ((uint64_t)access_size > sec->size - delta)
          continue;

        uint64_t file_offset =
          (uint64_t)sec->offset + delta;

        if (file_offset > size ||
          access_size > size - (size_t)file_offset) {
          continue;
        }

        return file_offset;
      }

      /*
       * Fall back to the segment mapping for bytes such as the Mach-O
       * header that may not belong to a section.
       */
      if (seg->filesize != 0 &&
        va >= seg->vmaddr) {
        uint64_t delta = va - seg->vmaddr;

        if (delta <= seg->filesize &&
          (uint64_t)access_size <= seg->filesize - delta) {
          uint64_t file_offset = seg->fileoff + delta;

          if (file_offset <= size &&
            access_size <= size - (size_t)file_offset) {
            return file_offset;
          }
        }
      }
    }

    lcp += cmdsize;
  }

  return UINT64_MAX;
}

#define KMOD_OFF_ADDR_64 156
#define KMOD_OFF_SIZE_64 164

int patch_kmod_info(LinkedKext *lk) {
  if (!lk ||
    !lk->linked_data ||
    lk->linked_size < sizeof(struct mach_header_64)) {
    fprintf(stderr,
        " patch_kmod_info: invalid linked kext\n");
    return -1;
  }

  if (!lk->kmod_info_addr) {
    fprintf(stderr,
        " patch_kmod_info: no defined _kmod_info symbol for %s\n",
        lk->bundle_id ? lk->bundle_id : "<unknown>");
    return -1;
  }

  /*
   * A kmod_info symbol belonging to this image must fall inside one of its
   * mapped segments. This catches accidentally resolved _kmod_info imports
   * before they patch an unrelated kext.
   */
  bool kmod_in_image = false;
  uint64_t image_start = UINT64_MAX;
  uint64_t image_end = 0;

  const struct mach_header_64 *mh =
    (const struct mach_header_64 *)lk->linked_data;

  if (mh->magic != MH_MAGIC_64) {
    fprintf(stderr,
        " patch_kmod_info: %s is not MH_MAGIC_64\n",
        lk->bundle_id ? lk->bundle_id : "<unknown>");
    return -1;
  }

  const uint8_t *lcp =
    lk->linked_data + sizeof(struct mach_header_64);

  for (uint32_t i = 0; i < mh->ncmds; i++) {
    size_t lc_offset =
      (size_t)(lcp - lk->linked_data);

    if (lc_offset > lk->linked_size ||
      lk->linked_size - lc_offset <
        sizeof(struct load_command)) {
      return -1;
    }

    uint32_t cmd = r32(lcp);
    uint32_t cmdsize = r32(lcp + 4);

    if (cmdsize < sizeof(struct load_command) ||
      cmdsize > lk->linked_size - lc_offset) {
      return -1;
    }

    if (cmd == LC_SEGMENT_64) {
      if (cmdsize < sizeof(struct segment_command_64))
        return -1;

      const struct segment_command_64 *seg =
        (const struct segment_command_64 *)lcp;

      if (seg->vmsize != 0) {
        uint64_t seg_end;

        if (UINT64_MAX - seg->vmaddr < seg->vmsize)
          return -1;

        seg_end = seg->vmaddr + seg->vmsize;

        if (seg->vmaddr < image_start)
          image_start = seg->vmaddr;

        if (seg_end > image_end)
          image_end = seg_end;

        if (lk->kmod_info_addr >= seg->vmaddr &&
          lk->kmod_info_addr < seg_end) {
          kmod_in_image = true;
        }
      }
    }

    lcp += cmdsize;
  }

  if (!kmod_in_image) {
    fprintf(stderr,
        " patch_kmod_info: %s has foreign kmod_info VA "
        "0x%llx; image range is 0x%llx-0x%llx\n",
        lk->bundle_id ? lk->bundle_id : "<unknown>",
        (unsigned long long)lk->kmod_info_addr,
        (unsigned long long)image_start,
        (unsigned long long)image_end);
    return -1;
  }

  uint64_t addr_va;
  uint64_t size_va;

  if (UINT64_MAX - lk->kmod_info_addr < KMOD_OFF_SIZE_64 + 8)
    return -1;

  addr_va = lk->kmod_info_addr + KMOD_OFF_ADDR_64;
  size_va = lk->kmod_info_addr + KMOD_OFF_SIZE_64;

  uint64_t addr_foff =
    va_to_foff(lk->linked_data,
           lk->linked_size,
           addr_va,
           sizeof(uint64_t));

  uint64_t size_foff =
    va_to_foff(lk->linked_data,
           lk->linked_size,
           size_va,
           sizeof(uint64_t));

  if (addr_foff == UINT64_MAX ||
    size_foff == UINT64_MAX) {
    fprintf(stderr,
        " patch_kmod_info: kmod_info VA 0x%llx not "
        "mappable to file offsets for %s\n",
        (unsigned long long)lk->kmod_info_addr,
        lk->bundle_id ? lk->bundle_id : "<unknown>");
    return -1;
  }

  /*
   * kmod_info.address and kmod_info.size describe the loaded module image,
   * not merely __TEXT. Use the complete mapped range.
   */
  if (image_start == UINT64_MAX || image_end <= image_start)
    return -1;

  uint64_t image_size = image_end - image_start;

  w64(lk->linked_data + addr_foff, image_start);
  w64(lk->linked_data + size_foff, image_size);

  fprintf(stderr,
      " patched kmod_info: %s "
      "kmod=0x%llx address=0x%llx size=0x%llx\n",
      lk->bundle_id ? lk->bundle_id : "<unknown>",
      (unsigned long long)lk->kmod_info_addr,
      (unsigned long long)image_start,
      (unsigned long long)image_size);

  return 0;
}

uint64_t symtab_lookup(const SymTable *st, const char *name) {
  size_t lo = 0, hi = st->count;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    int c = strcmp(st->syms[mid].name, name);
    if (!c)
      return st->syms[mid].addr;
    if (c < 0)
      lo = mid + 1; else hi = mid;
  }
  return 0;
}

static uint64_t find_defined_kmod_info(
    const struct nlist_64 *symbols,
    uint32_t symbol_count,
    const char *string_table,
    size_t string_table_size,
    const uint64_t *symbol_addresses)
{
    if (!symbols ||
        !string_table ||
        !symbol_addresses) {
        return 0;
    }

    for (uint32_t i = 0; i < symbol_count; i++) {
        const struct nlist_64 *n = &symbols[i];

        if (n->n_un.n_strx >= string_table_size)
            continue;

        const char *name =
            string_table + n->n_un.n_strx;

        size_t remaining =
            string_table_size - n->n_un.n_strx;

        if (!memchr(name, '\0', remaining))
            continue;

        if (strcmp(name, "_kmod_info") != 0 &&
            strcmp(name, "kmod_info") != 0) {
            continue;
        }

        /*
         * The critical condition: only accept a definition belonging to this
         * Mach-O. Never accept N_UNDF resolved from a prior kext.
         */
        uint8_t type = n->n_type & N_TYPE;

        if (type != N_SECT && type != N_ABS)
            continue;

        if (type == N_SECT && n->n_sect == NO_SECT)
            continue;

        if (!symbol_addresses[i])
            continue;

        return symbol_addresses[i];
    }

    return 0;
}

int link_kext(const uint8_t *kext_data, size_t kext_size,
              const SymTable *kernel_syms,
              uint64_t load_vmaddr,
              LinkedKext *out)
{
  size_t sl;
  const uint8_t *slice = find_slice(kext_data, kext_size, &sl);
  if (!slice) {
    fprintf(stderr, "link_kext: not a 64-bit Mach-O\n");
    return -1;
  }

  uint8_t *buf = malloc(sl);
  if (!buf)
    return -1;
  memcpy(buf, slice, sl);

  struct mach_header_64 *mh = (struct mach_header_64 *)buf;
  const struct symtab_command *symcmd = NULL;
  const uint8_t *dyld_info = NULL;   // LC_DYLD_INFO(_ONLY) command
  SegInfo seginfo[32];
  uint32_t nseginfo = 0;

  uint8_t *lcp = buf + sizeof(*mh);
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    uint32_t cmd = r32(lcp), sz = r32(lcp + 4);
    if (cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)lcp;
      seg->vmaddr += load_vmaddr;
      struct section_64 *secs = (struct section_64 *)(seg + 1);
      for (uint32_t j = 0; j < seg->nsects; j++)
        secs[j].addr += load_vmaddr;
      if (nseginfo < 32) {
        seginfo[nseginfo].fileoff = seg->fileoff;
        seginfo[nseginfo].vmaddr = seg->vmaddr - load_vmaddr;
        seginfo[nseginfo].filesize = seg->filesize;
        nseginfo++;
      }
    } else if (cmd == LC_SYMTAB) {
      symcmd = (const struct symtab_command *)lcp;
    } else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
      dyld_info = lcp;
    }
    lcp += sz;
  }

  if (!symcmd) {
    fprintf(stderr, "link_kext: no LC_SYMTAB\n");
    free(buf);
    return -1;
  }

  const struct nlist_64 *nl = (const struct nlist_64 *)(buf + symcmd->symoff);
  const char *strtab = (const char *)(buf + symcmd->stroff);
  uint32_t nsyms = symcmd->nsyms;

  uint64_t *sym_addrs = calloc(nsyms, sizeof(uint64_t));
  // mutable nlist pointer so we can write back resolved n_values
  struct nlist_64 *nl_mut = (struct nlist_64 *)(buf + symcmd->symoff);

  for (uint32_t i = 0; i < nsyms; i++) {
    const struct nlist_64 *n = &nl[i];
    uint8_t type = n->n_type & 0x0e;
    if (type == N_SECT) {
      // n_value is the symbol's vmaddr in the *original* (pre-slide) address space.
      // After the segment patch loop above, section.addr = original + load_vmaddr.
      //
      // So the symbol's final VA = (n_value - original_seg_vmaddr) + final_seg_vmaddr.
      // For kexts compiled at vmbase 0 this reduces to load_vmaddr + n_value, which is fine.
      // But store it as-is and let the write-back be the canonical source
      nl_mut[i].n_value = load_vmaddr + n->n_value;
      sym_addrs[i] = nl_mut[i].n_value;
    } else if (type == N_ABS) {
      sym_addrs[i] = n->n_value;
    } else if (type == N_UNDF) {
      const char *name = strtab + n->n_un.n_strx;
      uint64_t ka = symtab_lookup(kernel_syms, name);
      if (!ka && name[0] == '_')
        ka = symtab_lookup(kernel_syms, name + 1);
      if (ka)
        sym_addrs[i] = ka;
      else
        fprintf(stderr, "  UNRESOLVED: %s\n", name);
    }
  }

  typedef struct { uint32_t foff; uint64_t vmaddr; uint32_t size; } SecRef;
  SecRef *sec_refs = NULL;
  uint32_t total_sects = 0;
  {
    uint8_t *p = buf + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = r32(p), sz = r32(p + 4);
      if (cmd == LC_SEGMENT_64)
        total_sects += ((const struct segment_command_64 *)p)->nsects;
      p += sz;
    }
    sec_refs = calloc(total_sects, sizeof(SecRef));
    uint32_t si = 0;
    p = buf + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = r32(p), sz = r32(p + 4);
      if (cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
        const struct section_64 *secs = (const struct section_64 *)(seg + 1);
        for (uint32_t j = 0; j < seg->nsects; j++) {
          sec_refs[si].foff   = secs[j].offset;
          sec_refs[si].vmaddr = secs[j].addr;
          sec_refs[si].size   = (uint32_t)secs[j].size;
          si++;
        }
      }
      p += sz;
    }
  }

  uint32_t nerrs = 0;
  {
    uint8_t *p = buf + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = r32(p), sz = r32(p + 4);
      if (cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
        const struct section_64 *secs = (const struct section_64 *)(seg + 1);
        for (uint32_t j = 0; j < seg->nsects; j++) {
          const struct section_64 *sec = &secs[j];
          if (!sec->nreloc || !sec->reloff)
            continue;

          const struct relocation_info *relocs = (const struct relocation_info *)(buf + sec->reloff);
          for (uint32_t ri = 0; ri < sec->nreloc; ri++) {
            struct relocation_info r = relocs[ri];

            if (r.r_type == X86_64_RELOC_SUBTRACTOR) {
              if (ri + 1 >= sec->nreloc) continue;
              struct relocation_info r2 = relocs[++ri];
              if ((uint32_t)r.r_address + 8 > sec->size)
                continue;
              uint8_t *loc = buf + sec->offset + r.r_address;
              uint64_t sym_b = r.r_extern  ? sym_addrs[r.r_symbolnum]
                                           : (r.r_symbolnum  ? sec_refs[r.r_symbolnum - 1].vmaddr  : load_vmaddr);
              uint64_t sym_a = r2.r_extern ? sym_addrs[r2.r_symbolnum]
                                           : (r2.r_symbolnum ? sec_refs[r2.r_symbolnum - 1].vmaddr : load_vmaddr);
              uint64_t addend = (r2.r_length == RL_QUAD) ? r64(loc) : (uint64_t)(uint32_t)r32(loc);
              uint64_t val = sym_a - sym_b + addend;
              if (r2.r_length == RL_QUAD)
                w64(loc, val);
              else
                w32(loc, (uint32_t)val);
              continue;
            }

            if ((uint32_t)r.r_address >= sec->size)
              continue;

            uint8_t *loc = buf + sec->offset + r.r_address;
            uint64_t pc  = sec->addr + (uint32_t)r.r_address;

            uint64_t target = 0;
            if (r.r_extern) {
              if (r.r_symbolnum < nsyms)
                target = sym_addrs[r.r_symbolnum];
              if (!target) nerrs++;
            } else {
              uint32_t si2 = r.r_symbolnum;
              if (si2 >= 1 && si2 <= total_sects)
                target = sec_refs[si2 - 1].vmaddr;
            }

            switch (r.r_type) {
            case X86_64_RELOC_UNSIGNED: {
              uint64_t addend = r64(loc);
              w64(loc, target + addend);
              break;
            }
            case X86_64_RELOC_BRANCH:
            case X86_64_RELOC_SIGNED:
            case X86_64_RELOC_SIGNED_1:
            case X86_64_RELOC_SIGNED_2:
            case X86_64_RELOC_SIGNED_4: {
              int extra = (r.r_type == X86_64_RELOC_SIGNED_1) ? 1 :
                          (r.r_type == X86_64_RELOC_SIGNED_2) ? 2 :
                          (r.r_type == X86_64_RELOC_SIGNED_4) ? 4 : 0;
              int32_t addend = (int32_t)r32(loc);
              int64_t rel = (int64_t)target - (int64_t)(pc + 4 + extra) + addend;
              w32(loc, (uint32_t)(int32_t)rel);
              break;
            }
            case X86_64_RELOC_GOT_LOAD:
            case X86_64_RELOC_GOT: {
              int32_t addend = (int32_t)r32(loc);
              int64_t rel = (int64_t)target - (int64_t)(pc + 4) + addend;
              if (rel < -2147483648LL || rel > 2147483647LL)
                fprintf(stderr, "  WARN: GOT ref out of 32-bit range (rel=%lld)\n", (long long)rel);
              w32(loc, (uint32_t)(int32_t)rel);
              break;
            }
            default:
              fprintf(stderr, "  WARN: unhandled reloc type %u\n", r.r_type);
              break;
            }
          }
        }
      }
      p += sz;
    }
  }

  if (nerrs)
    fprintf(stderr, "  link_kext: %u unresolved symbols\n", nerrs);

  if (dyld_info && nseginfo) {
    const struct dyld_info_command *di = (const struct dyld_info_command *)dyld_info;

    uint64_t trampoline = symtab_lookup(kernel_syms, "_panic");
    if (!trampoline)
      trampoline = symtab_lookup(kernel_syms, "panic");

    // Map a (segment index, segment offset) target to a file location in buf.
    #define TARGET_LOC(seg_ix, seg_off) \
      ((seg_ix) < nseginfo ? buf + seginfo[seg_ix].fileoff + (seg_off) : NULL)

    // Rebase: add the slide (load_vmaddr) to each pointer slot.
    if (di->rebase_size) {
      const uint8_t *p   = buf + di->rebase_off;
      const uint8_t *end = p + di->rebase_size;
      uint32_t seg_ix = 0;
      uint64_t seg_off = 0;
      int done = 0;
      while (p < end && !done) {
        uint8_t op  = *p & REBASE_OPCODE_MASK;
        uint8_t imm = *p & REBASE_IMMEDIATE_MASK;
        p++;
        switch (op) {
        case REBASE_OPCODE_DONE:
          done = 1;
          break;
        case REBASE_OPCODE_SET_TYPE_IMM:
          break; // only pointer rebases matter for x86_64 kexts
        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
          seg_ix = imm;
          seg_off = read_uleb(&p, end);
          break;
        case REBASE_OPCODE_ADD_ADDR_ULEB:
          seg_off += read_uleb(&p, end);
          break;
        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
          seg_off += (uint64_t)imm * 8;
          break;
        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
          for (uint32_t k = 0; k < imm; k++) {
            uint8_t *loc = TARGET_LOC(seg_ix, seg_off);
            if (loc) w64(loc, r64(loc) + load_vmaddr);
            seg_off += 8;
          }
          break;
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
          uint64_t cnt = read_uleb(&p, end);
          for (uint64_t k = 0; k < cnt; k++) {
            uint8_t *loc = TARGET_LOC(seg_ix, seg_off);
            if (loc) w64(loc, r64(loc) + load_vmaddr);
            seg_off += 8;
          }
          break;
        }
        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
          uint8_t *loc = TARGET_LOC(seg_ix, seg_off);
          if (loc) w64(loc, r64(loc) + load_vmaddr);
          seg_off += 8 + read_uleb(&p, end);
          break;
        }
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
          uint64_t cnt  = read_uleb(&p, end);
          uint64_t skip = read_uleb(&p, end);
          for (uint64_t k = 0; k < cnt; k++) {
            uint8_t *loc = TARGET_LOC(seg_ix, seg_off);
            if (loc) w64(loc, r64(loc) + load_vmaddr);
            seg_off += 8 + skip;
          }
          break;
        }
        default:
          fprintf(stderr, "  rebase: unknown opcode 0x%x\n", op);
          done = 1;
          break;
        }
      }
    }

    // Bind + lazy bind: resolve each named symbol and write its address.
    for (int pass = 0; pass < 2; pass++) {
      uint32_t boff = pass ? di->lazy_bind_off  : di->bind_off;
      uint32_t bsz  = pass ? di->lazy_bind_size : di->bind_size;
      if (!bsz)
        continue;
      const uint8_t *p   = buf + boff;
      const uint8_t *end = p + bsz;
      uint32_t seg_ix = 0;
      uint64_t seg_off = 0;
      int64_t  addend = 0;
      const char *sym = NULL;
      uint64_t symval = 0;
      int done = 0;
      #define RESOLVE_SYM() do { \
        symval = sym ? symtab_lookup(kernel_syms, sym) : 0; \
        if (!symval && sym && sym[0] == '_') symval = symtab_lookup(kernel_syms, sym + 1); \
        if (!symval) { \
          if (sym && strcmp(sym, "dyld_stub_binder")) \
            fprintf(stderr, "  BIND UNRESOLVED (-> panic trampoline): %s\n", sym); \
          symval = trampoline; \
        } \
      } while (0)
      #define DO_ONE_BIND() do { \
        uint8_t *loc = TARGET_LOC(seg_ix, seg_off); \
        if (loc && symval) w64(loc, symval + addend); \
        seg_off += 8; \
      } while (0)
      while (p < end && !done) {
        uint8_t op  = *p & BIND_OPCODE_MASK;
        uint8_t imm = *p & BIND_IMMEDIATE_MASK;
        p++;
        switch (op) {
        case BIND_OPCODE_DONE:
          if (pass == 1)
            break; // lazy: DONE marks end of each entry, keep going
          done = 1;
          break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
          break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
          read_uleb(&p, end);
          break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
          sym = (const char *)p;
          while (p < end && *p)
            p++;
          if (p < end)
            p++; // skip NUL
          RESOLVE_SYM();
          break;
        case BIND_OPCODE_SET_TYPE_IMM:
          break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
          addend = read_sleb(&p, end);
          break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
          seg_ix = imm; seg_off = read_uleb(&p, end);
          break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
          seg_off += read_uleb(&p, end);
          break;
        case BIND_OPCODE_DO_BIND:
          DO_ONE_BIND();
          break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
          DO_ONE_BIND();
          seg_off += read_uleb(&p, end);
          break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
          DO_ONE_BIND();
          seg_off += (uint64_t)imm * 8;
          break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
          uint64_t cnt  = read_uleb(&p, end);
          uint64_t skip = read_uleb(&p, end);
          for (uint64_t k = 0; k < cnt; k++) {
            uint8_t *loc = TARGET_LOC(seg_ix, seg_off);
            if (loc && symval) w64(loc, symval + addend);
            seg_off += 8 + skip;
          }
          break;
        }
        default:
          fprintf(stderr, "  bind: unknown opcode 0x%x\n", op);
          done = 1;
          break;
        }
      }
      #undef RESOLVE_SYM
      #undef DO_ONE_BIND
    }
    #undef TARGET_LOC
  }

  size_t strtab_size = 0;

  if ((uint64_t)symcmd->stroff <= sl)
    strtab_size = sl - symcmd->stroff;

  uint64_t kmod_info_addr = find_defined_kmod_info(nl, nsyms, strtab, strtab_size, sym_addrs);

  free(sym_addrs);
  free(sec_refs);

  out->linked_data = buf;
  out->linked_size = sl;
  out->load_vmaddr = load_vmaddr;
  out->kmod_info_addr = kmod_info_addr;
  return 0;
}
