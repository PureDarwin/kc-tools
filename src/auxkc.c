/*
 * Auxiliary kernel collection: kexts linked against a boot KC, loaded by xnu
 * from a file after boot (OSKext::loadKCFileSet with KCKindAuxiliary).
 *
 * xnu maps the file wherever the kext map has room and slides it as a whole:
 * mapKCTextSegment takes the slide as (mapping - __TEXT.vmaddr), so the
 * collection is linked at 0 and every pointer is a chained fixup. Pointers
 * into this collection use cache level 3 (xnu's auxiliary_kc_index), pointers into the boot KC level 0.
 *
 * The file is a plain VM image, file offset == unslid vmaddr:
 *   __TEXT          the collection header and its load commands
 *   __PRELINK_TEXT  the kexts, each still a complete Mach-O
 *   __PRELINK_INFO  _PrelinkInfoDictionary plus _PrelinkKCID and _BootKCID
 *   __LINKEDIT      the chained fixups
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auxkc.h"
#include "macho_fmt.h"
#include "plist.h"

#define PAGE 0x1000ULL
#define ALIGN_UP(x, a) (((uint64_t)(x) + ((uint64_t)(a) - 1)) & ~((uint64_t)(a) - 1))

#ifndef LC_DYLD_INFO
#define LC_DYLD_INFO 0x22
#endif
#ifndef LC_DYLD_INFO_ONLY
#define LC_DYLD_INFO_ONLY (0x22 | 0x80000000)
#endif
#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE (0x33 | 0x80000000)
#endif
#define CPU_SUBTYPE_X86_64_ALL 3
#define KC_LEVEL_PRIMARY 0
#define KC_LEVEL_AUX 3
#define KC_PTR_64_KERNEL_CACHE 8

struct uuid_lc {
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
};

struct dyld_info_lc {
  uint32_t cmd, cmdsize;
  uint32_t rebase_off, rebase_size, bind_off, bind_size;
  uint32_t weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size;
  uint32_t export_off, export_size;
};

// two FNV-1a passes with different seeds, good enough to tell collections apart
void kc_uuid_hash(const void *data, size_t len, uint8_t io_uuid[16])
{
  uint64_t h[2];
  memcpy(h, io_uuid, 16);
  if (!h[0] && !h[1]) {
    h[0] = 0xcbf29ce484222325ULL;
    h[1] = 0x84222325cbf29ce4ULL;
  }
  const uint8_t *p = data;
  for (size_t i = 0; i < len; i++) {
    h[0] = (h[0] ^ p[i]) * 0x100000001b3ULL;
    h[1] = (h[1] ^ p[i]) * 0x100000001b3ULL ^ (h[0] >> 29);
  }
  memcpy(io_uuid, h, 16);
}

void kc_uuid_finish(uint8_t uuid[16])
{
  uuid[6] = (uuid[6] & 0x0f) | 0x40;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
}

// a linked kext's offsets are relative to its own start, the collection needs them absolute
static int shift_kext_offsets(uint8_t *mh_base, uint32_t delta)
{
  struct mach_header_64 *mh = (struct mach_header_64 *)mh_base;
  uint8_t *lcp = mh_base + sizeof(*mh);

#define SHIFT(f) do { if (f) (f) += delta; } while (0)
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    struct load_command *lc = (struct load_command *)lcp;

    switch (lc->cmd) {
    case LC_SEGMENT_64: {
      struct segment_command_64 *sc = (struct segment_command_64 *)lcp;
      struct section_64 *sects = (struct section_64 *)(sc + 1);

      if (sc->filesize || sc->fileoff)
        sc->fileoff += delta;
      for (uint32_t n = 0; n < sc->nsects; n++) {
        if (sects[n].offset)
          sects[n].offset += delta;
        SHIFT(sects[n].reloff);
      }
      break;
    }
    case LC_SYMTAB: {
      struct symtab_command *st = (struct symtab_command *)lcp;
      SHIFT(st->symoff);
      SHIFT(st->stroff);
      break;
    }
    case LC_DYSYMTAB: {
      struct dysymtab_command *d = (struct dysymtab_command *)lcp;
      SHIFT(d->tocoff);
      SHIFT(d->modtaboff);
      SHIFT(d->extrefsymoff);
      SHIFT(d->indirectsymoff);
      SHIFT(d->extreloff);
      SHIFT(d->locreloff);
      break;
    }
    case LC_DYLD_INFO:
    case LC_DYLD_INFO_ONLY: {
      struct dyld_info_lc *d = (struct dyld_info_lc *)lcp;
      SHIFT(d->rebase_off);
      SHIFT(d->bind_off);
      SHIFT(d->weak_bind_off);
      SHIFT(d->lazy_bind_off);
      SHIFT(d->export_off);
      break;
    }
    case LC_FUNCTION_STARTS:
    case LC_DATA_IN_CODE:
    case LC_DYLD_CHAINED_FIXUPS:
    case LC_DYLD_EXPORTS_TRIE: {
      struct linkedit_data_command *ld = (struct linkedit_data_command *)lcp;
      SHIFT(ld->dataoff);
      break;
    }
    default:
      break;
    }
    lcp += lc->cmdsize;
  }
#undef SHIFT
  return 0;
}

// a kext's own __LINKEDIT, as offsets relative to the kext's start
static int kext_linkedit(const uint8_t *mh_base, uint64_t *fileoff, uint64_t *filesize)
{
  const struct mach_header_64 *mh = (const struct mach_header_64 *)mh_base;
  const uint8_t *lcp = mh_base + sizeof(*mh);

  for (uint32_t i = 0; i < mh->ncmds; i++) {
    const struct load_command *lc = (const struct load_command *)lcp;
    if (lc->cmd == LC_SEGMENT_64 && !strncmp(((const struct segment_command_64 *)lcp)->segname, "__LINKEDIT", 16)) {
      *fileoff = ((const struct segment_command_64 *)lcp)->fileoff;
      *filesize = ((const struct segment_command_64 *)lcp)->filesize;
      return 0;
    }
    lcp += lc->cmdsize;
  }
  return -1;
}

/*
 * xnu never maps a kext's own __LINKEDIT in a collection, yet it slides every
 * kext's symbols through it, so they have to live in the collection's mapped
 * __LINKEDIT: move the bytes there, repoint the offsets and the segment.
 */
static void move_kext_linkedit(uint8_t *mh_base, uint64_t old_off, uint64_t size, uint64_t new_off,
                               uint64_t link_vm, uint64_t link_size)
{
  struct mach_header_64 *mh = (struct mach_header_64 *)mh_base;
  uint8_t *lcp = mh_base + sizeof(*mh);
  uint32_t delta = (uint32_t)(new_off - old_off);

#define MOVE(f) do { if ((f) >= old_off && (f) < old_off + size) (f) += delta; } while (0)
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    struct load_command *lc = (struct load_command *)lcp;

    switch (lc->cmd) {
    case LC_SEGMENT_64: {
      struct segment_command_64 *sc = (struct segment_command_64 *)lcp;
      if (!strncmp(sc->segname, "__LINKEDIT", 16)) {
        sc->vmaddr = link_vm;
        sc->vmsize = link_size;
        sc->fileoff = link_vm;
        sc->filesize = link_size;
      }
      break;
    }
    case LC_SYMTAB: {
      struct symtab_command *st = (struct symtab_command *)lcp;
      MOVE(st->symoff);
      MOVE(st->stroff);
      break;
    }
    case LC_DYSYMTAB: {
      struct dysymtab_command *d = (struct dysymtab_command *)lcp;
      MOVE(d->tocoff);
      MOVE(d->modtaboff);
      MOVE(d->extrefsymoff);
      MOVE(d->indirectsymoff);
      MOVE(d->extreloff);
      MOVE(d->locreloff);
      break;
    }
    case LC_DYLD_INFO:
    case LC_DYLD_INFO_ONLY: {
      struct dyld_info_lc *d = (struct dyld_info_lc *)lcp;
      MOVE(d->rebase_off);
      MOVE(d->bind_off);
      MOVE(d->weak_bind_off);
      MOVE(d->lazy_bind_off);
      MOVE(d->export_off);
      break;
    }
    case LC_FUNCTION_STARTS:
    case LC_DATA_IN_CODE:
    case LC_DYLD_CHAINED_FIXUPS:
    case LC_DYLD_EXPORTS_TRIE: {
      struct linkedit_data_command *ld = (struct linkedit_data_command *)lcp;
      MOVE(ld->dataoff);
      break;
    }
    default:
      break;
    }
    lcp += lc->cmdsize;
  }
#undef MOVE
}

static int site_cmp(const void *a, const void *b)
{
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y;
}

// one chain per page over the kexts' pointer slots, each slot rewritten as level + offset
static int build_fixups(uint8_t *buf, size_t size, const LinkedKext *kexts, size_t n,
                        uint64_t text_vm, uint64_t text_size, uint32_t nsegs, uint32_t text_seg,
                        uint64_t aux_end, uint64_t boot_base,
                        uint8_t **out_blob, uint32_t *out_size)
{
  size_t nsites = 0;
  for (size_t k = 0; k < n; k++)
    nsites += kexts[k].nptr_slots;

  uint64_t *sites = calloc(nsites ? nsites : 1, sizeof(*sites));
  if (!sites)
    return -1;
  size_t m = 0;
  for (size_t k = 0; k < n; k++)
    for (size_t s = 0; s < kexts[k].nptr_slots; s++)
      sites[m++] = kexts[k].ptr_slots[s];
  qsort(sites, m, sizeof(*sites), site_cmp);

  uint32_t pages = (uint32_t)(ALIGN_UP(text_size, PAGE) / PAGE);
  uint32_t seginfo_size = 22 + pages * 2;
  uint32_t starts_size = 4 + nsegs * 4 + seginfo_size;
  uint32_t blob_size = (uint32_t)sizeof(struct dyld_chained_fixups_header) + starts_size;
  uint8_t *blob = calloc(1, blob_size);
  if (!blob) {
    free(sites);
    return -1;
  }

  struct dyld_chained_fixups_header *fh = (struct dyld_chained_fixups_header *)blob;
  fh->starts_offset = sizeof(*fh);
  fh->imports_offset = blob_size;
  fh->symbols_offset = blob_size;
  fh->imports_format = 1;

  uint8_t *sp = blob + sizeof(*fh);
  uint32_t *seg_offs = (uint32_t *)(sp + 4);
  uint8_t *info = sp + 4 + nsegs * 4;
  *(uint32_t *)sp = nsegs;
  seg_offs[text_seg] = (uint32_t)(info - sp);
  *(uint32_t *)(info + 0) = seginfo_size;
  *(uint16_t *)(info + 4) = (uint16_t)PAGE;
  *(uint16_t *)(info + 6) = KC_PTR_64_KERNEL_CACHE;
  *(uint64_t *)(info + 8) = text_vm;
  *(uint32_t *)(info + 16) = 0;
  *(uint16_t *)(info + 20) = (uint16_t)pages;
  uint16_t *page_start = (uint16_t *)(info + 22);
  for (uint32_t p = 0; p < pages; p++)
    page_start[p] = 0xffff;

  uint64_t prev = 0;
  uint32_t open_page = UINT32_MAX, used = 0, to_aux = 0, to_boot = 0, bad = 0;
  for (size_t i = 0; i < m; i++) {
    uint64_t vm = sites[i];

    if (i && vm == sites[i - 1])
      continue;
    if (vm < text_vm || vm + 8 > text_vm + text_size || vm + 8 > size || (vm & 3))
      continue;

    uint64_t v = *(uint64_t *)(buf + vm), raw;
    // chained fixups cannot encode NULL, leave it plain
    if (v == 0)
      continue;
    if (v < aux_end) {
      raw = v | ((uint64_t)KC_LEVEL_AUX << 30);
      to_aux++;
    } else if (v >= boot_base && v - boot_base < (1ULL << 30)) {
      raw = (v - boot_base) | ((uint64_t)KC_LEVEL_PRIMARY << 30);
      to_boot++;
    } else {
      fprintf(stderr, "auxkc: pointer at 0x%llx to 0x%llx is in neither collection\n",
              (unsigned long long)vm, (unsigned long long)v);
      bad++;
      continue;
    }
    *(uint64_t *)(buf + vm) = raw;

    uint64_t off = vm - text_vm;
    uint32_t page = (uint32_t)(off / PAGE);
    if (page != open_page) {
      page_start[page] = (uint16_t)(off & (PAGE - 1));
      open_page = page;
    } else {
      uint64_t prevv = *(uint64_t *)(buf + prev);
      prevv &= ~(0xfffULL << 51);
      prevv |= (((vm - prev) / 4) & 0xfffULL) << 51;
      *(uint64_t *)(buf + prev) = prevv;
    }
    prev = vm;
    used++;
  }
  fprintf(stderr, "auxkc: %u pointers chained, %u into this collection, %u into the boot KC, %u unresolvable\n",
          used, to_aux, to_boot, bad);
  free(sites);
  if (bad) {
    free(blob);
    return -1;
  }
  *out_blob = blob;
  *out_size = blob_size;
  return 0;
}

static void put_seg(uint8_t **lcp, uint32_t *ncmds, const char *name, uint64_t vm, uint64_t vmsize,
                    uint64_t fileoff, uint64_t filesize, uint32_t prot,
                    const char *sectname, uint64_t sect_addr, uint64_t sect_size)
{
  struct segment_command_64 *sc = (struct segment_command_64 *)*lcp;
  uint32_t nsects = sectname ? 1 : 0;

  sc->cmd = LC_SEGMENT_64;
  sc->cmdsize = (uint32_t)(sizeof(*sc) + nsects * sizeof(struct section_64));
  strncpy(sc->segname, name, sizeof(sc->segname));
  sc->vmaddr = vm;
  sc->vmsize = vmsize;
  sc->fileoff = fileoff;
  sc->filesize = filesize;
  sc->maxprot = prot;
  sc->initprot = prot;
  sc->nsects = nsects;
  if (nsects) {
    struct section_64 *s = (struct section_64 *)(sc + 1);
    strncpy(s->sectname, sectname, sizeof(s->sectname));
    strncpy(s->segname, name, sizeof(s->segname));
    s->addr = sect_addr;
    s->size = sect_size;
    s->offset = (uint32_t)sect_addr;
  }
  *lcp += sc->cmdsize;
  (*ncmds)++;
}

int auxkc_assemble(LinkedKext *kexts, size_t n, uint64_t boot_base,
                   const uint8_t boot_uuid[16], const uint8_t aux_uuid[16],
                   uint8_t **out_data, size_t *out_size)
{
  uint64_t text_vm = AUXKC_HEADER_SIZE, text_end = text_vm;

  for (size_t i = 0; i < n; i++) {
    if (kexts[i].codeless)
      continue;
    uint64_t occupied = kexts[i].vm_extent ? kexts[i].vm_extent : kexts[i].linked_size;
    uint64_t end = kexts[i].load_vmaddr + ALIGN_UP(occupied, PAGE);
    if (kexts[i].load_vmaddr < text_vm) {
      fprintf(stderr, "auxkc: %s linked at 0x%llx, inside the collection header\n",
              kexts[i].bundle_id, (unsigned long long)kexts[i].load_vmaddr);
      return -1;
    }
    if (end > text_end)
      text_end = end;
  }
  text_end = ALIGN_UP(text_end, PAGE);

  // the info dictionary, with the ids xnu checks before it takes the collection
  PlistNode *arr = plist_new_array();
  for (size_t i = 0; i < n; i++) {
    LinkedKext *k = &kexts[i];
    PlistNode *d = k->info_plist_xml ? plist_parse(k->info_plist_xml, k->info_plist_len) : NULL;

    if (!d || d->type != PLIST_DICT) {
      if (d)
        plist_free(d);
      d = plist_new_dict();
    }
    plist_dict_set(d, "_PrelinkBundlePath", plist_new_string(k->bundle_path));
    if (!k->codeless) {
      plist_dict_set(d, "_PrelinkExecutableLoadAddr", plist_new_integer(k->load_vmaddr));
      plist_dict_set(d, "_PrelinkExecutableFileOffset", plist_new_integer(k->load_vmaddr));
      plist_dict_set(d, "_PrelinkExecutableSize", plist_new_integer(ALIGN_UP(k->linked_size, PAGE)));
      plist_dict_set(d, "_PrelinkExecutableSourceAddr", plist_new_integer(k->load_vmaddr));
      plist_dict_set(d, "_PrelinkKmodInfo", plist_new_integer(k->kmod_info_addr));
    }
    plist_array_append(arr, d);
  }
  PlistNode *root = plist_new_dict();
  plist_dict_set(root, "_PrelinkInfoDictionary", arr);
  plist_dict_set(root, "_PrelinkKCID", plist_new_data(aux_uuid, 16));
  plist_dict_set(root, "_BootKCID", plist_new_data(boot_uuid, 16));
  size_t xml_len = 0;
  char *xml = plist_write_xml(root, &xml_len);
  plist_free(root);
  if (!xml)
    return -1;

  uint64_t info_vm = text_end, info_size = ALIGN_UP(xml_len + 1, PAGE);
  uint64_t link_vm = info_vm + info_size;
  // the fixup blob size depends only on the page count, so size it before writing pointers
  uint32_t nsegs = 4, text_seg = 1;
  uint64_t est_blob = sizeof(struct dyld_chained_fixups_header) + 4 + nsegs * 4 + 22 +
                      2 * (ALIGN_UP(text_end - text_vm, PAGE) / PAGE);
  // the kexts' symbol tables follow the fixups in the collection's __LINKEDIT
  uint64_t kext_link_total = 0;
  for (size_t i = 0; i < n; i++) {
    uint64_t lo, ls;
    if (!kexts[i].codeless && kext_linkedit(kexts[i].linked_data, &lo, &ls) == 0)
      kext_link_total += ALIGN_UP(ls, 16);
  }
  uint64_t link_size = ALIGN_UP(ALIGN_UP(est_blob, 16) + kext_link_total, PAGE);
  size_t total = (size_t)(link_vm + link_size);

  uint8_t *buf = calloc(1, total);
  if (!buf) {
    free(xml);
    return -1;
  }

  for (size_t i = 0; i < n; i++) {
    LinkedKext *k = &kexts[i];
    if (k->codeless)
      continue;
    memcpy(buf + k->load_vmaddr, k->linked_data, k->linked_size);
    struct mach_header_64 *kmh = (struct mach_header_64 *)(buf + k->load_vmaddr);
    kmh->flags |= MH_DYLIB_IN_CACHE;
    shift_kext_offsets(buf + k->load_vmaddr, (uint32_t)k->load_vmaddr);
  }
  uint64_t link_cursor = link_vm + ALIGN_UP(est_blob, 16);
  for (size_t i = 0; i < n; i++) {
    LinkedKext *k = &kexts[i];
    uint64_t lo, ls;
    if (k->codeless || kext_linkedit(buf + k->load_vmaddr, &lo, &ls) != 0 || !ls)
      continue;
    memcpy(buf + link_cursor, buf + lo, ls);
    move_kext_linkedit(buf + k->load_vmaddr, lo, ls, link_cursor, link_vm, link_size);
    link_cursor += ALIGN_UP(ls, 16);
  }
  memcpy(buf + info_vm, xml, xml_len);
  free(xml);

  uint8_t *blob = NULL;
  uint32_t blob_size = 0;
  if (build_fixups(buf, total, kexts, n, text_vm, text_end - text_vm, nsegs, text_seg,
                   text_end, boot_base, &blob, &blob_size) != 0) {
    free(buf);
    return -1;
  }
  memcpy(buf + link_vm, blob, blob_size);
  free(blob);

  struct mach_header_64 *mh = (struct mach_header_64 *)buf;
  uint8_t *lcp = buf + sizeof(*mh);
  uint32_t ncmds = 0;

  mh->magic = MH_MAGIC_64;
  mh->cputype = CPU_TYPE_X86_64;
  mh->cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  mh->filetype = MH_FILESET;
  mh->flags = MH_DYLIB_IN_CACHE;

  put_seg(&lcp, &ncmds, "__TEXT", 0, AUXKC_HEADER_SIZE, 0, AUXKC_HEADER_SIZE, VM_PROT_READ, NULL, 0, 0);
  put_seg(&lcp, &ncmds, "__PRELINK_TEXT", text_vm, text_end - text_vm, text_vm, text_end - text_vm,
          VM_PROT_READ | VM_PROT_EXECUTE, NULL, 0, 0);
  put_seg(&lcp, &ncmds, "__PRELINK_INFO", info_vm, info_size, info_vm, info_size,
          VM_PROT_READ | VM_PROT_WRITE, "__info", info_vm, xml_len + 1);
  // xnu slides every kext's symbols in place here, so it has to be writable when mapped
  put_seg(&lcp, &ncmds, "__LINKEDIT", link_vm, link_size, link_vm, link_size, VM_PROT_READ | VM_PROT_WRITE, NULL, 0, 0);

  struct uuid_lc *u = (struct uuid_lc *)lcp;
  u->cmd = LC_UUID;
  u->cmdsize = sizeof(*u);
  memcpy(u->uuid, aux_uuid, 16);
  lcp += sizeof(*u);
  ncmds++;

  struct linkedit_data_command *cf = (struct linkedit_data_command *)lcp;
  cf->cmd = LC_DYLD_CHAINED_FIXUPS;
  cf->cmdsize = sizeof(*cf);
  cf->dataoff = (uint32_t)link_vm;
  cf->datasize = blob_size;
  lcp += sizeof(*cf);
  ncmds++;

  for (size_t i = 0; i < n; i++) {
    LinkedKext *k = &kexts[i];
    if (k->codeless)
      continue;
    uint32_t idlen = (uint32_t)strlen(k->bundle_id) + 1;
    uint32_t cs = (uint32_t)ALIGN_UP(sizeof(struct fileset_entry_command) + idlen, 8);
    if ((uint64_t)(lcp - buf) + cs > AUXKC_HEADER_SIZE) {
      fprintf(stderr, "auxkc: too many kexts for a 0x%llx byte header\n",
              (unsigned long long)AUXKC_HEADER_SIZE);
      free(buf);
      return -1;
    }
    struct fileset_entry_command *fe = (struct fileset_entry_command *)lcp;
    fe->cmd = LC_FILESET_ENTRY;
    fe->cmdsize = cs;
    fe->vmaddr = k->load_vmaddr;
    fe->fileoff = k->load_vmaddr;
    fe->entry_id = sizeof(*fe);
    memcpy(lcp + sizeof(*fe), k->bundle_id, idlen);
    lcp += cs;
    ncmds++;
  }
  mh->ncmds = ncmds;
  mh->sizeofcmds = (uint32_t)(lcp - (buf + sizeof(*mh)));

  *out_data = buf;
  *out_size = total;
  return 0;
}
