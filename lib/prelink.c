#include "prelink.h"
#include "plist.h"
#include "macho_fmt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PAGE 0x1000ULL
#define ALIGN_UP(x, a) (((uint64_t)(x) + ((uint64_t)(a) - 1)) & ~((uint64_t)(a) - 1))

static void put32(uint8_t *p, uint32_t v) {
  p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static void put64(uint8_t *p, uint64_t v) {
  put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32));
}

int prelink_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size)
{
  const struct mach_header_64 *mh = (const struct mach_header_64 *)kernel_data;
  if (mh->magic != MH_MAGIC_64) {
    fprintf(stderr, "prelink: kernel is not MH_MAGIC_64 (got 0x%x)\n", mh->magic);
    return -1;
  }

  // Find highest kernel VM address for kext placement.
  // Skip zero-size placeholder __PRELINK_TEXT (vmsize=0) segments.
  uint64_t kernel_vm_end = 0;
  {
    const uint8_t *lcp = kernel_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc = (const struct segment_command_64 *)lcp;
        if (sc->vmsize > 0) {
          uint64_t end = sc->vmaddr + sc->vmsize;
          if (end > kernel_vm_end) kernel_vm_end = end;
        }
      }
      lcp += lc->cmdsize;
    }
  }
  kernel_vm_end = ALIGN_UP(kernel_vm_end, PAGE * 64);
  fprintf(stderr, "prelink: kernel vm end = 0x%llx\n",
          (unsigned long long)kernel_vm_end);

  // VMaddrs were already assigned by the caller (main.c).
  // Compute __PRELINK_TEXT extent from the kexts' actual load_vmaddrs.
  uint64_t prelink_text_vmaddr = kexts[0].load_vmaddr;
  uint64_t kext_end = prelink_text_vmaddr;
  for (size_t i = 0; i < num_kexts; i++) {
    if (kexts[i].codeless) continue;   // no code to place
    uint64_t end = kexts[i].load_vmaddr + ALIGN_UP(kexts[i].linked_size, PAGE);
    if (end > kext_end) kext_end = end;
    fprintf(stderr, "  kext[%zu] %s: vmaddr=0x%llx size=0x%zx kmod_info=0x%llx\n",
            i, kexts[i].bundle_id,
            (unsigned long long)kexts[i].load_vmaddr,
            kexts[i].linked_size,
            (unsigned long long)kexts[i].kmod_info_addr);
  }
  uint64_t prelink_text_vmsize = kext_end - prelink_text_vmaddr;

  // Compute the file-layout values that the plist needs.
  // prelink_text_fileoff only depends on kernel_size, so it's safe here.
  size_t prelink_text_fileoff = ALIGN_UP(kernel_size, PAGE);

  PlistNode *info_array = plist_new_array();
  for (size_t i = 0; i < num_kexts; i++) {
    LinkedKext *k = &kexts[i];
    PlistNode *dict = NULL;
    if (k->info_plist_xml && k->info_plist_len)
      dict = plist_parse(k->info_plist_xml, k->info_plist_len);
    if (!dict || dict->type != PLIST_DICT) {
      if (dict) plist_free(dict);
      dict = plist_new_dict();
    }
    plist_dict_set(dict, "_PrelinkBundlePath",            plist_new_string(k->bundle_path));
    if (!k->codeless) {
      // Real kext: full executable placement keys.
      uint64_t file_off = prelink_text_fileoff + (k->load_vmaddr - prelink_text_vmaddr);
      plist_dict_set(dict, "_PrelinkExecutableLoadAddr",    plist_new_integer(k->load_vmaddr));
      plist_dict_set(dict, "_PrelinkExecutableFileOffset",  plist_new_integer(file_off));
      plist_dict_set(dict, "_PrelinkExecutableSize",        plist_new_integer(ALIGN_UP(k->linked_size, PAGE)));
      plist_dict_set(dict, "_PrelinkExecutableSourceAddr",  plist_new_integer(k->load_vmaddr));
      plist_dict_set(dict, "_PrelinkKmodInfo",              plist_new_integer(k->kmod_info_addr));
    }
    plist_array_append(info_array, dict);
  }
  PlistNode *info_root = plist_new_dict();
  plist_dict_set(info_root, "_PrelinkInfoDictionary", info_array);
  size_t info_xml_len = 0;
  char *info_xml = plist_write_xml(info_root, &info_xml_len);
  plist_free(info_root);

  // Now that info_xml_len is known, compute the rest of the layout.
  uint64_t prelink_info_vmaddr = ALIGN_UP(kext_end, PAGE * 4);
  uint64_t prelink_info_vmsize = ALIGN_UP(info_xml_len + 1, PAGE);
  size_t prelink_info_fileoff = ALIGN_UP(prelink_text_fileoff + prelink_text_vmsize, PAGE);
  size_t total_size = prelink_info_fileoff + prelink_info_vmsize;

  // Find existing zero-size __PRELINK_TEXT, __PRELINK_DATA, __PRELINK_INFO
  // placeholders to patch in-place. If not found we append new load commands.
  struct segment_command_64 *existing_pt = NULL;  // __PRELINK_TEXT
  struct segment_command_64 *existing_pd = NULL;  // __PRELINK_DATA
  struct segment_command_64 *existing_pi = NULL;  // __PRELINK_INFO
  {
    // Use a mutable copy (will be the output buf), but scan original for now.
    const uint8_t *lcp = kernel_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc = (const struct segment_command_64 *)lcp;
        if (!memcmp(sc->segname, "__PRELINK_TEXT", 14) && sc->vmsize == 0)
          existing_pt = (struct segment_command_64 *)lcp;
        if (!memcmp(sc->segname, "__PRELINK_DATA", 14) && sc->vmsize == 0)
          existing_pd = (struct segment_command_64 *)lcp;
        if (!memcmp(sc->segname, "__PRELINK_INFO", 14) && sc->vmsize == 0)
          existing_pi = (struct segment_command_64 *)lcp;
      }
      lcp += lc->cmdsize;
    }
  }

  // How many new LCs do we need to append?
  size_t extra_lc = 0;
  if (!existing_pt)
    extra_lc += sizeof(struct segment_command_64) + sizeof(struct section_64);
  if (!existing_pd)
    extra_lc += sizeof(struct segment_command_64) + sizeof(struct section_64);
  if (!existing_pi)
    extra_lc += sizeof(struct segment_command_64) + sizeof(struct section_64);

  // Find where kernel segment data starts (first non-zero fileoff).
  uint64_t kernel_body_off = 0;
  {
    const uint8_t *lcp = kernel_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc = (const struct segment_command_64 *)lcp;
        if (sc->filesize > 0 && (!kernel_body_off || sc->fileoff < kernel_body_off))
          kernel_body_off = sc->fileoff;
      }
      lcp += lc->cmdsize;
    }
  }
  if (!kernel_body_off)
    kernel_body_off = PAGE;

  if (extra_lc > 0) {
    size_t cur_hdr_end = sizeof(*mh) + mh->sizeofcmds;
    if (cur_hdr_end + extra_lc > kernel_body_off) {
      fprintf(stderr, "prelink: no room for %zu bytes of new LCs "
              "(header ends at 0x%zx, body at 0x%llx)\n",
              extra_lc, cur_hdr_end, (unsigned long long)kernel_body_off);
      free(info_xml);
      return -1;
    }
  }

  uint8_t *out = calloc(1, total_size);
  if (!out) { free(info_xml); return -1; }
  memcpy(out, kernel_data, kernel_size);

  // Write kext binaries into __PRELINK_TEXT region and patch filetype.
  for (size_t i = 0; i < num_kexts; i++) {
    LinkedKext *k = &kexts[i];
    if (k->codeless || !k->linked_data) continue;   // codeless: no code
    size_t kext_file_base = prelink_text_fileoff + (k->load_vmaddr - prelink_text_vmaddr);
    if (kext_file_base + k->linked_size > total_size)
      continue;
    memcpy(out + kext_file_base, k->linked_data, k->linked_size);

    struct mach_header_64 *kmh = (struct mach_header_64 *)(out + kext_file_base);
    if (kmh->magic != MH_MAGIC_64)
      continue;

    // Fix filetype: MH_BUNDLE -> MH_KEXT_BUNDLE.
    if (kmh->filetype == MH_BUNDLE)
      kmh->filetype = MH_KEXT_BUNDLE;

    // Clear flags that are invalid for kexts: MH_TWOLEVEL (0x4),
    // MH_NOFIXPREBINDING (0x80). Leave MH_NOUNDEFS (0x1).
    kmh->flags &= ~(0x4u | 0x80u);

    // Strip load commands that are dyld-specific and invalid in MH_KEXT_BUNDLE.
    // IDA validates that kexts don't have these. Compact the LC area in-place.
    {
      uint8_t *lc_base  = (uint8_t *)(kmh + 1);
      uint8_t *lc_read  = lc_base;
      uint8_t *lc_write = lc_base;
      uint32_t new_ncmds = 0, new_szcmds = 0;
      for (uint32_t ci = 0; ci < kmh->ncmds; ci++) {
        uint32_t cmd = *(uint32_t *)lc_read;
        uint32_t csz = *(uint32_t *)(lc_read + 4);
        int drop = (cmd == 0x22 || cmd == 0x80000022 || // LC_DYLD_INFO(_ONLY)
                    cmd == 0x0c || // LC_LOAD_DYLIB
                    cmd == 0x80000018 || // LC_LOAD_WEAK_DYLIB
                    cmd == 0x28 || // LC_LAZY_LOAD_DYLIB
                    cmd == 0x1d || // LC_CODE_SIGNATURE
                    cmd == 0x2c);  // LC_DYLD_ENVIRONMENT
        if (!drop) {
          if (lc_write != lc_read)
            memmove(lc_write, lc_read, csz);
          lc_write += csz;
          new_ncmds++;
          new_szcmds += csz;
        }
        lc_read += csz;
      }
      // Zero the vacated space.
      if (lc_write < lc_read)
        memset(lc_write, 0, (size_t)(lc_read - lc_write));
      kmh->ncmds = new_ncmds;
      kmh->sizeofcmds = new_szcmds;
    }
  }

  // Write __PRELINK_INFO XML.
  memcpy(out + prelink_info_fileoff, info_xml, info_xml_len);
  free(info_xml);

  // Pointer fixup: existing_pt/pd/pi point into kernel_data; rebase to out.
  ptrdiff_t rebase = (ptrdiff_t)(out - kernel_data);
  if (existing_pt)
    existing_pt = (struct segment_command_64 *)((uint8_t *)existing_pt + rebase);
  if (existing_pd)
    existing_pd = (struct segment_command_64 *)((uint8_t *)existing_pd + rebase);
  if (existing_pi)
    existing_pi = (struct segment_command_64 *)((uint8_t *)existing_pi + rebase);

  struct mach_header_64 *new_mh = (struct mach_header_64 *)out;
  uint8_t *lc_end = out + sizeof(*new_mh) + new_mh->sizeofcmds;

  // Helper to fill a segment + one section.
  #define FILL_SEG(sc, sname, vm, vsz, foff, fsz, mp, ip, stype) do { \
    memset(sc, 0, sizeof(*(sc)) + sizeof(struct section_64)); \
    (sc)->cmd      = LC_SEGMENT_64; \
    (sc)->cmdsize  = sizeof(*(sc)) + sizeof(struct section_64); \
    memcpy((sc)->segname, sname, strlen(sname)); \
    (sc)->vmaddr   = (vm); \
    (sc)->vmsize   = (vsz); \
    (sc)->fileoff  = (foff); \
    (sc)->filesize = (fsz); \
    (sc)->maxprot  = (mp); \
    (sc)->initprot = (ip); \
    (sc)->nsects   = 1; \
  } while (0)

  #define FILL_SECT(sect, stn, sgn, a, sz, off, aln) do { \
    memcpy((sect)->sectname, stn, strlen(stn)); \
    memcpy((sect)->segname,  sgn, strlen(sgn)); \
    (sect)->addr   = (a); \
    (sect)->size   = (sz); \
    (sect)->offset = (uint32_t)(off); \
    (sect)->align  = (aln); \
  } while (0)

  // __PRELINK_TEXT
  if (existing_pt) {
    FILL_SEG(existing_pt, "__PRELINK_TEXT",
             prelink_text_vmaddr, prelink_text_vmsize,
             prelink_text_fileoff, prelink_text_vmsize,
             VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
    struct section_64 *sect = (struct section_64 *)(existing_pt + 1);
    FILL_SECT(sect, "__text", "__PRELINK_TEXT",
              prelink_text_vmaddr, prelink_text_vmsize, prelink_text_fileoff, 12);
  } else {
    struct segment_command_64 *sc = (struct segment_command_64 *)lc_end;
    FILL_SEG(sc, "__PRELINK_TEXT",
             prelink_text_vmaddr, prelink_text_vmsize,
             prelink_text_fileoff, prelink_text_vmsize,
             VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, 0);
    struct section_64 *sect = (struct section_64 *)(sc + 1);
    FILL_SECT(sect, "__text", "__PRELINK_TEXT",
              prelink_text_vmaddr, prelink_text_vmsize, prelink_text_fileoff, 12);
    lc_end += sc->cmdsize;
    new_mh->ncmds++;
    new_mh->sizeofcmds += sc->cmdsize;
  }

  // __PRELINK_DATA (empty placeholder between __PRELINK_TEXT and __PRELINK_INFO)
  uint64_t pd_vmaddr = prelink_info_vmaddr - PAGE;
  if (existing_pd) {
    FILL_SEG(existing_pd, "__PRELINK_DATA",
             pd_vmaddr, PAGE, 0, 0,
             VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0);
    struct section_64 *sect = (struct section_64 *)(existing_pd + 1);
    FILL_SECT(sect, "__data", "__PRELINK_DATA", pd_vmaddr, 0, 0, 0);
  } else {
    struct segment_command_64 *sc = (struct segment_command_64 *)lc_end;
    FILL_SEG(sc, "__PRELINK_DATA",
             pd_vmaddr, PAGE, 0, 0,
             VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0);
    struct section_64 *sect = (struct section_64 *)(sc + 1);
    FILL_SECT(sect, "__data", "__PRELINK_DATA", pd_vmaddr, 0, 0, 0);
    lc_end += sc->cmdsize;
    new_mh->ncmds++;
    new_mh->sizeofcmds += sc->cmdsize;
  }

  // __PRELINK_INFO
  if (existing_pi) {
    FILL_SEG(existing_pi, "__PRELINK_INFO",
             prelink_info_vmaddr, prelink_info_vmsize,
             prelink_info_fileoff, info_xml_len + 1,
             VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0);
    struct section_64 *sect = (struct section_64 *)(existing_pi + 1);
    FILL_SECT(sect, "__info", "__PRELINK_INFO",
              prelink_info_vmaddr, info_xml_len + 1, prelink_info_fileoff, 0);
  } else {
    struct segment_command_64 *sc = (struct segment_command_64 *)lc_end;
    FILL_SEG(sc, "__PRELINK_INFO",
             prelink_info_vmaddr, prelink_info_vmsize,
             prelink_info_fileoff, info_xml_len + 1,
             VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, 0);
    struct section_64 *sect = (struct section_64 *)(sc + 1);
    FILL_SECT(sect, "__info", "__PRELINK_INFO",
              prelink_info_vmaddr, info_xml_len + 1, prelink_info_fileoff, 0);
    lc_end += sc->cmdsize;
    new_mh->ncmds++;
    new_mh->sizeofcmds += sc->cmdsize;
  }

  #undef FILL_SEG
  #undef FILL_SECT

  (void)put64;

  *out_data = out;
  *out_size = total_size;
  return 0;
}

static int segname_is(const char n[16], const char *s) {
  size_t l = strlen(s);
  return !memcmp(n, s, l) && (l >= 16 || n[l] == '\0');
}

static void buf_append(uint8_t **buf, size_t *len, size_t *cap, const void *data, size_t n) {
  if (*len + n > *cap) {
    *cap = (*len + n) * 2 + (1 << 20);
    *buf = realloc(*buf, *cap);
  }
  if (data)
    memcpy(*buf + *len, data, n);
  else
    memset(*buf + *len, 0, n);
  *len += n;
}

int prelink_assemble_merged(const uint8_t *kernel_data, size_t kernel_size,
                            LinkedKext *kexts, size_t num_kexts,
                            uint8_t **out_data, size_t *out_size,
                            size_t *out_header_foffs)
{
  const struct mach_header_64 *mh = (const struct mach_header_64 *)kernel_data;
  if (mh->magic != MH_MAGIC_64) {
    fprintf(stderr, "prelink_merged: kernel is not MH_MAGIC_64 (got 0x%x)\n", mh->magic);
    return -1;
  }

  uint8_t *pool_buf[3] = { NULL, NULL, NULL };
  size_t pool_len[3] = { 0, 0, 0 };
  size_t pool_cap[3] = { 0, 0, 0 };
  size_t *header_pool_off = calloc(num_kexts, sizeof(size_t));
  int *header_in_pool1 = calloc(num_kexts, sizeof(int));

  for (int pool = 0; pool < 3; pool++) {
    for (size_t i = 0; i < num_kexts; i++) {
      if (kexts[i].codeless || !kexts[i].linked_data) continue;
      const uint8_t *kdata = kexts[i].linked_data;
      const struct mach_header_64 *kmh = (const struct mach_header_64 *)kdata;
      const uint8_t *klcp = kdata + sizeof(*kmh);
      for (uint32_t j = 0; j < kmh->ncmds; j++) {
        const struct load_command *lc = (const struct load_command *)klcp;
        if (lc->cmd == LC_SEGMENT_64) {
          const struct segment_command_64 *sc = (const struct segment_command_64 *)klcp;
          int is_data_const = segname_is(sc->segname, "__DATA_CONST");
          int is_text = segname_is(sc->segname, "__TEXT");
          int matches = (pool == 0 && is_data_const) ||
                        (pool == 1 && is_text) ||
                        (pool == 2 && !is_data_const && !is_text);
          if (matches) {
            if (pool == 1 && sc->fileoff == 0) {
              header_pool_off[i] = pool_len[1];
              header_in_pool1[i] = 1;
            }
            buf_append(&pool_buf[pool], &pool_len[pool], &pool_cap[pool],
                      kdata + sc->fileoff, sc->filesize);
            uint64_t padded = ALIGN_UP(sc->vmsize ? sc->vmsize : 1, PAGE);
            if (padded > sc->filesize)
              buf_append(&pool_buf[pool], &pool_len[pool], &pool_cap[pool],
                        NULL, padded - sc->filesize);
          }
        }
        klcp += lc->cmdsize;
      }
    }
    pool_len[pool] = ALIGN_UP(pool_len[pool], PAGE);
  }

  uint8_t *out = NULL;
  size_t out_len = 0, out_cap = 0;
  int64_t shift = 0;
  size_t pool_file_start[3] = { 0, 0, 0 };

  const uint8_t *lcp = kernel_data + sizeof(*mh);
  uint64_t prev_end = 0;
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    const struct load_command *lc = (const struct load_command *)lcp;
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *sc = (const struct segment_command_64 *)lcp;
      if (sc->filesize > 0 && sc->fileoff > prev_end)
        prev_end = sc->fileoff + sc->filesize;
      else if (sc->filesize > 0)
        prev_end = sc->fileoff + sc->filesize;
    }
    lcp += lc->cmdsize;
  }
  (void)prev_end;

  buf_append(&out, &out_len, &out_cap, kernel_data, kernel_size);

  // __PLK_DATA_CONST/__PLK_TEXT_EXEC/__PRELINK_DATA all start out coincident
  // (same vmaddr, same fileoff) as empty placeholders reserved by the
  // kernel's own link step. As each pool's content is inserted, later pools
  // must be placed both after it in the file *and* above it in VM space -
  // otherwise their vmaddr collides with content that's actually at a
  // different file location. kc_builder.c's placement pass computes the
  // exact same cumulative layout ahead of linking so kext relocations agree
  // with what ends up here.
  uint64_t plk_vm_cursor = 0;
  int have_plk_base = 0;

  for (int pool = 0; pool < 3; pool++) {
    const char *name = pool == 0 ? "__PLK_DATA_CONST" : pool == 1 ? "__PLK_TEXT_EXEC" : "__PRELINK_DATA";
    struct segment_command_64 *sc = NULL;
    uint8_t *lcp2 = out + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = *(uint32_t *)lcp2, csz = *(uint32_t *)(lcp2 + 4);
      if (cmd == LC_SEGMENT_64) {
        struct segment_command_64 *s = (struct segment_command_64 *)lcp2;
        if (segname_is(s->segname, name)) { sc = s; break; }
      }
      lcp2 += csz;
    }
    if (!sc || pool_len[pool] == 0) continue;

    if (!have_plk_base) { plk_vm_cursor = sc->vmaddr; have_plk_base = 1; }
    sc->vmaddr = plk_vm_cursor;

    size_t insert_at = sc->fileoff + sc->filesize;
    size_t tail_len = out_len - insert_at;
    uint8_t *tail = malloc(tail_len);
    memcpy(tail, out + insert_at, tail_len);

    pool_file_start[pool] = insert_at;
    out_len = insert_at;
    buf_append(&out, &out_len, &out_cap, pool_buf[pool], pool_len[pool]);
    buf_append(&out, &out_len, &out_cap, tail, tail_len);
    free(tail);

    sc->filesize += pool_len[pool];
    sc->vmsize = sc->filesize > sc->vmsize ? sc->filesize : sc->vmsize;
    plk_vm_cursor += ALIGN_UP(sc->vmsize, PAGE);

    int64_t this_shift = (int64_t)pool_len[pool];
    uint8_t *lcp3 = out + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = *(uint32_t *)lcp3, csz = *(uint32_t *)(lcp3 + 4);
      if (cmd == LC_SEGMENT_64) {
        struct segment_command_64 *s = (struct segment_command_64 *)lcp3;
        if (s != sc && s->fileoff >= insert_at)
          s->fileoff += this_shift;
      } else if (cmd == LC_SYMTAB) {
        struct symtab_command *st = (struct symtab_command *)lcp3;
        if (st->symoff >= insert_at) st->symoff += (uint32_t)this_shift;
        if (st->stroff >= insert_at) st->stroff += (uint32_t)this_shift;
      }
      lcp3 += csz;
    }
    shift += this_shift;
  }
  (void)shift;

  for (size_t i = 0; i < num_kexts; i++) {
    if (header_in_pool1[i])
      out_header_foffs[i] = pool_file_start[1] + header_pool_off[i];
    else
      out_header_foffs[i] = 0;
  }
  free(header_pool_off);
  free(header_in_pool1);
  free(pool_buf[0]); free(pool_buf[1]); free(pool_buf[2]);

  struct mach_header_64 *new_mh = (struct mach_header_64 *)out;

  uint64_t kext_end = 0;
  for (size_t i = 0; i < num_kexts; i++) {
    if (kexts[i].codeless) continue;
    uint64_t e = kexts[i].header_vmaddr + ALIGN_UP(kexts[i].linked_size, PAGE);
    if (e > kext_end) kext_end = e;
  }
  if (kext_end == 0) {
    const uint8_t *lcp4 = kernel_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp4;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc = (const struct segment_command_64 *)lcp4;
        uint64_t e = sc->vmaddr + sc->vmsize;
        if (e > kext_end) kext_end = e;
      }
      lcp4 += lc->cmdsize;
    }
  }

  PlistNode *info_array = plist_new_array();
  for (size_t i = 0; i < num_kexts; i++) {
    LinkedKext *k = &kexts[i];
    PlistNode *dict = NULL;
    if (k->info_plist_xml && k->info_plist_len)
      dict = plist_parse(k->info_plist_xml, k->info_plist_len);
    if (!dict || dict->type != PLIST_DICT) {
      if (dict) plist_free(dict);
      dict = plist_new_dict();
    }
    plist_dict_set(dict, "_PrelinkBundlePath", plist_new_string(k->bundle_path));
    if (!k->codeless) {
      plist_dict_set(dict, "_PrelinkExecutableLoadAddr", plist_new_integer(k->header_vmaddr));
      plist_dict_set(dict, "_PrelinkExecutableFileOffset", plist_new_integer(out_header_foffs[i]));
      plist_dict_set(dict, "_PrelinkExecutableSize", plist_new_integer(ALIGN_UP(k->linked_size, PAGE)));
      plist_dict_set(dict, "_PrelinkExecutableSourceAddr", plist_new_integer(k->header_vmaddr));
      plist_dict_set(dict, "_PrelinkKmodInfo", plist_new_integer(k->kmod_info_addr));
    }
    plist_array_append(info_array, dict);
  }
  PlistNode *info_root = plist_new_dict();
  plist_dict_set(info_root, "_PrelinkInfoDictionary", info_array);
  size_t info_xml_len = 0;
  char *info_xml = plist_write_xml(info_root, &info_xml_len);
  plist_free(info_root);

  uint64_t prelink_info_vmaddr = ALIGN_UP(kext_end, PAGE * 4);
  uint64_t prelink_info_vmsize = ALIGN_UP(info_xml_len + 1, PAGE);
  size_t prelink_info_fileoff = ALIGN_UP(out_len, PAGE);
  size_t total_size = prelink_info_fileoff + prelink_info_vmsize;

  struct segment_command_64 *existing_pi = NULL;
  {
    uint8_t *lcp5 = out + sizeof(*new_mh);
    for (uint32_t i = 0; i < new_mh->ncmds; i++) {
      struct load_command *lc = (struct load_command *)lcp5;
      if (lc->cmd == LC_SEGMENT_64) {
        struct segment_command_64 *sc = (struct segment_command_64 *)lcp5;
        if (segname_is(sc->segname, "__PRELINK_INFO") && sc->vmsize == 0)
          existing_pi = sc;
      }
      lcp5 += lc->cmdsize;
    }
  }

  size_t final_size = total_size > out_len ? total_size : out_len;
  uint8_t *final_out = calloc(1, final_size);
  memcpy(final_out, out, out_len);
  free(out);
  memcpy(final_out + prelink_info_fileoff, info_xml, info_xml_len);
  free(info_xml);

  new_mh = (struct mach_header_64 *)final_out;
  if (existing_pi) {
    existing_pi = (struct segment_command_64 *)(final_out + ((uint8_t *)existing_pi - out));
  }
  if (existing_pi) {
    existing_pi->vmaddr = prelink_info_vmaddr;
    existing_pi->vmsize = prelink_info_vmsize;
    existing_pi->fileoff = prelink_info_fileoff;
    existing_pi->filesize = info_xml_len + 1;
    struct section_64 *sect = (struct section_64 *)(existing_pi + 1);
    memset(sect, 0, sizeof(*sect));
    memcpy(sect->sectname, "__info", 6);
    memcpy(sect->segname, "__PRELINK_INFO", 14);
    sect->addr = prelink_info_vmaddr;
    sect->size = info_xml_len + 1;
    sect->offset = (uint32_t)prelink_info_fileoff;
  } else {
    uint8_t *lc_end = final_out + sizeof(*new_mh) + new_mh->sizeofcmds;
    struct segment_command_64 *sc = (struct segment_command_64 *)lc_end;
    memset(sc, 0, sizeof(*sc) + sizeof(struct section_64));
    sc->cmd = LC_SEGMENT_64;
    sc->cmdsize = sizeof(*sc) + sizeof(struct section_64);
    memcpy(sc->segname, "__PRELINK_INFO", 14);
    sc->vmaddr = prelink_info_vmaddr;
    sc->vmsize = prelink_info_vmsize;
    sc->fileoff = prelink_info_fileoff;
    sc->filesize = info_xml_len + 1;
    sc->maxprot = VM_PROT_READ | VM_PROT_WRITE;
    sc->initprot = VM_PROT_READ | VM_PROT_WRITE;
    sc->nsects = 1;
    struct section_64 *sect = (struct section_64 *)(sc + 1);
    memset(sect, 0, sizeof(*sect));
    memcpy(sect->sectname, "__info", 6);
    memcpy(sect->segname, "__PRELINK_INFO", 14);
    sect->addr = prelink_info_vmaddr;
    sect->size = info_xml_len + 1;
    sect->offset = (uint32_t)prelink_info_fileoff;
    new_mh->ncmds++;
    new_mh->sizeofcmds += sc->cmdsize;
  }

  *out_data = final_out;
  *out_size = final_size;
  return 0;
}

// Real-KC assembler: grows __TEXT_EXEC/__DATA_CONST/__DATA (the actual
// segments) in place to hold kext content, anchored at the position of the
// matching __PLK_TEXT_EXEC/__PLK_DATA_CONST/__PRELINK_DATA placeholder
// (which stays a zero-size marker forever, per arm_vm_init.c's asserts).
// No __PRELINK_TEXT/__PRELINK_INFO content is written; those placeholders
// stay untouched too.
int prelink_assemble_kc(const uint8_t *kernel_data, size_t kernel_size,
                        LinkedKext *kexts, size_t num_kexts,
                        uint8_t **out_data, size_t *out_size,
                        size_t *out_header_foffs)
{
  const struct mach_header_64 *mh = (const struct mach_header_64 *)kernel_data;
  if (mh->magic != MH_MAGIC_64) {
    fprintf(stderr, "prelink_kc: kernel is not MH_MAGIC_64 (got 0x%x)\n", mh->magic);
    return -1;
  }

  uint8_t *pool_buf[3] = { NULL, NULL, NULL };
  size_t pool_len[3] = { 0, 0, 0 };
  size_t pool_cap[3] = { 0, 0, 0 };
  size_t *header_pool_off = calloc(num_kexts, sizeof(size_t));
  int *header_pool = calloc(num_kexts, sizeof(int));
  for (size_t i = 0; i < num_kexts; i++) header_pool[i] = -1;

  for (int pool = 0; pool < 3; pool++) {
    for (size_t i = 0; i < num_kexts; i++) {
      if (kexts[i].codeless || !kexts[i].linked_data) continue;
      const uint8_t *kdata = kexts[i].linked_data;
      const struct mach_header_64 *kmh = (const struct mach_header_64 *)kdata;
      const uint8_t *klcp = kdata + sizeof(*kmh);
      for (uint32_t j = 0; j < kmh->ncmds; j++) {
        const struct load_command *lc = (const struct load_command *)klcp;
        if (lc->cmd == LC_SEGMENT_64) {
          const struct segment_command_64 *sc = (const struct segment_command_64 *)klcp;
          int is_data_const = segname_is(sc->segname, "__DATA_CONST");
          int is_text = segname_is(sc->segname, "__TEXT");
          int matches = (pool == 0 && is_data_const) ||
                        (pool == 1 && is_text) ||
                        (pool == 2 && !is_data_const && !is_text);
          if (matches) {
            if (sc->fileoff == 0 && header_pool[i] == -1) {
              header_pool_off[i] = pool_len[pool];
              header_pool[i] = pool;
            }
            buf_append(&pool_buf[pool], &pool_len[pool], &pool_cap[pool],
                      kdata + sc->fileoff, sc->filesize);
            uint64_t padded = ALIGN_UP(sc->vmsize ? sc->vmsize : 1, PAGE);
            if (padded > sc->filesize)
              buf_append(&pool_buf[pool], &pool_len[pool], &pool_cap[pool],
                        NULL, padded - sc->filesize);
          }
        }
        klcp += lc->cmdsize;
      }
    }
    pool_len[pool] = ALIGN_UP(pool_len[pool], PAGE);
  }

  uint8_t *out = NULL;
  size_t out_len = 0, out_cap = 0;
  buf_append(&out, &out_len, &out_cap, kernel_data, kernel_size);

  size_t pool_file_start[3] = { 0, 0, 0 };
  static const char *anchor_name[3] = { "__PLK_DATA_CONST", "__PLK_TEXT_EXEC", "__PRELINK_DATA" };
  static const char *target_name[3] = { "__DATA_CONST", "__TEXT_EXEC", "__DATA" };

  for (int pool = 0; pool < 3; pool++) {
    struct segment_command_64 *anchor = NULL, *target = NULL;
    uint8_t *lcp2 = out + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      uint32_t cmd = *(uint32_t *)lcp2, csz = *(uint32_t *)(lcp2 + 4);
      if (cmd == LC_SEGMENT_64) {
        struct segment_command_64 *s = (struct segment_command_64 *)lcp2;
        if (segname_is(s->segname, anchor_name[pool])) anchor = s;
        else if (segname_is(s->segname, target_name[pool])) target = s;
      }
      lcp2 += csz;
    }
    if (!anchor || !target) continue;

    uint64_t anchor_vmaddr = anchor->vmaddr;
    size_t insert_at = anchor->fileoff + anchor->filesize;

    if (pool_len[pool] > 0) {
      size_t tail_len = out_len - insert_at;
      uint8_t *tail = malloc(tail_len);
      memcpy(tail, out + insert_at, tail_len);

      pool_file_start[pool] = insert_at;
      out_len = insert_at;
      buf_append(&out, &out_len, &out_cap, pool_buf[pool], pool_len[pool]);
      buf_append(&out, &out_len, &out_cap, tail, tail_len);
      free(tail);

      target->filesize += pool_len[pool];

      int64_t this_shift = (int64_t)pool_len[pool];
      uint8_t *lcp3 = out + sizeof(struct mach_header_64);
      for (uint32_t i = 0; i < mh->ncmds; i++) {
        uint32_t cmd = *(uint32_t *)lcp3, csz = *(uint32_t *)(lcp3 + 4);
        if (cmd == LC_SEGMENT_64) {
          struct segment_command_64 *s = (struct segment_command_64 *)lcp3;
          if (s->fileoff >= insert_at && s != target)
            s->fileoff += this_shift;
        } else if (cmd == LC_SYMTAB) {
          struct symtab_command *st = (struct symtab_command *)lcp3;
          if (st->symoff >= insert_at) st->symoff += (uint32_t)this_shift;
          if (st->stroff >= insert_at) st->stroff += (uint32_t)this_shift;
        }
        lcp3 += csz;
      }
    }

    // Ensure target reaches at least through the anchor's (pre-shift)
    // position plus any inserted content, even if pool_len == 0 (still
    // swallows the gap up to __LASTDATA_CONST/kernel __DATA's end).
    uint64_t required_end = anchor_vmaddr + pool_len[pool];
    if (required_end > target->vmaddr + target->vmsize)
      target->vmsize = required_end - target->vmaddr;
  }

  for (size_t i = 0; i < num_kexts; i++) {
    out_header_foffs[i] = (header_pool[i] >= 0)
        ? pool_file_start[header_pool[i]] + header_pool_off[i] : 0;
  }
  free(header_pool_off);
  free(header_pool);
  free(pool_buf[0]); free(pool_buf[1]); free(pool_buf[2]);

  // Leave trailing slack after __LINKEDIT's content for fileset_assemble to
  // append the chained-fixups blob without growing the file further.
  size_t padded_len = ALIGN_UP(out_len + PAGE, PAGE);
  buf_append(&out, &out_len, &out_cap, NULL, padded_len - out_len);

  *out_data = out;
  *out_size = out_len;
  return 0;
}