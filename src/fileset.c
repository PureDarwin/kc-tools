#include "prelink.h"
#include "plist.h"
#include "macho_fmt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PAGE 0x1000ULL
#define ALIGN_UP(x, a) (((uint64_t)(x) + ((uint64_t)(a) - 1)) & ~((uint64_t)(a) - 1))

#define DYLD_CHAINED_PTR_64_KERNEL_CACHE 8
#define DYLD_CHAINED_PTR_START_NONE 0xffff
#define DYLD_CHAINED_PTR_START_MULTI 0x8000
#define DYLD_CHAINED_PTR_START_LAST 0x8000
#define MH_SPLIT_SEGS 0x20
#define ARM64_RELOC_UNSIGNED 0

typedef struct {
  uint64_t fileoff;
  uint32_t seg_index;
} FixupSite;

/* The kernel's original LC_UNIXTHREAD is not authoritative after it has
 * been turned into a collection.  In particular, some XNU builds carry a
 * stale ARM64 entry there.  The loader still uses that command, so recover
 * the real bootstrap entry from the preserved symbol table. */
static uint64_t
kernel_arm64_start(const uint8_t *data, size_t data_size,
    const struct mach_header_64 *mh)
{
  const struct symtab_command *symtab = NULL;
  const uint8_t *p = data + sizeof(*mh);
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    const struct load_command *lc = (const struct load_command *)p;
    if (lc->cmd == LC_SYMTAB)
      symtab = (const struct symtab_command *)p;
    p += lc->cmdsize;
  }
  if (!symtab || symtab->symoff > data_size ||
      (uint64_t)symtab->symoff + (uint64_t)symtab->nsyms * sizeof(struct nlist_64) > data_size ||
      symtab->stroff > data_size ||
      (uint64_t)symtab->stroff + symtab->strsize > data_size)
    return 0;

  const struct nlist_64 *symbols =
      (const struct nlist_64 *)(data + symtab->symoff);
  const char *strings = (const char *)(data + symtab->stroff);
  for (uint32_t i = 0; i < symtab->nsyms; i++) {
    uint32_t strx = symbols[i].n_un.n_strx;
    if (strx >= symtab->strsize)
      continue;
    if (!strcmp(strings + strx, "_start"))
      return symbols[i].n_value;
  }
  return 0;
}

static void
kernel_arm64_set_entry(uint8_t *data, size_t data_size,
    const struct mach_header_64 *mh, uint64_t entry)
{
  if (!entry)
    return;
  uint8_t *p = data + sizeof(*mh);
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    struct load_command *lc = (struct load_command *)p;
    if (lc->cmd == LC_UNIXTHREAD) {
      uint8_t *q = p + sizeof(struct load_command);
      uint8_t *end = p + lc->cmdsize;
      while (q + 8 <= end) {
        uint32_t flavor = *(uint32_t *)q;
        uint32_t count = *(uint32_t *)(q + 4);
        uint8_t *state = q + 8;
        uint64_t state_size = (uint64_t)count * sizeof(uint32_t);
        if (state + state_size > end)
          return;
        if (flavor == 6 /* ARM_THREAD_STATE64 */ && state_size >= 33 * sizeof(uint64_t)) {
          /* x[0..28], fp, lr, sp, pc: pc is qword 32. */
          *(uint64_t *)(state + 32 * sizeof(uint64_t)) = entry;
          fprintf(stderr, "fileset: ARM64 LC_UNIXTHREAD entry -> 0x%llx\n",
              (unsigned long long)entry);
          return;
        }
        q = state + state_size;
      }
      return;
    }
    p += lc->cmdsize;
  }
  (void)data_size;
}

static int
fixup_site_compare(const void *a, const void *b)
{
  const FixupSite *fa = a;
  const FixupSite *fb = b;
  return fa->fileoff < fb->fileoff ? -1 : fa->fileoff > fb->fileoff;
}

/* Convert the kernel's local absolute relocations to the kernel-cache chain
 * format. The ARM64 XNU kernel is linked as a PIE with classic local relocs;
 * a fileset KC must carry the equivalent DYLD_CHAINED_PTR_64_KERNEL_CACHE
 * records because XNU's KC bootstrapper only consumes chained fixups. */
static int
build_kernel_cache_fixups(uint8_t *data, size_t data_size,
    const struct mach_header_64 *mh,
    const struct segment_command_64 *const *segs, size_t nsegs,
    uint64_t base_vmaddr,
    uint8_t **out_blob, uint32_t *out_size)
{
  const struct dysymtab_command *dysymtab = NULL;
  const uint8_t *p = data + sizeof(*mh);
  for (uint32_t i = 0; i < mh->ncmds; i++) {
    const struct load_command *lc = (const struct load_command *)p;
    if (lc->cmd == LC_DYSYMTAB)
      dysymtab = (const struct dysymtab_command *)p;
    p += lc->cmdsize;
  }
  if (!dysymtab || dysymtab->nlocrel == 0)
    return -1;
  uint64_t rel_end = (uint64_t)dysymtab->locreloff +
      (uint64_t)dysymtab->nlocrel * sizeof(struct relocation_info);
  if (rel_end > data_size)
    return -1;

  uint32_t first = UINT32_MAX;
  for (size_t i = 0; i < nsegs; i++) {
    if (segs[i]->fileoff == 0 && first == UINT32_MAX)
      first = (uint32_t)i;
  }
  if (first == UINT32_MAX)
    return -1;

  FixupSite **sites = calloc(nsegs, sizeof(*sites));
  uint32_t *counts = calloc(nsegs, sizeof(*counts));
  uint32_t *caps = calloc(nsegs, sizeof(*caps));
  if (!sites || !counts || !caps) goto fail;

  const struct relocation_info *relocs =
      (const struct relocation_info *)(data + dysymtab->locreloff);
  for (uint32_t i = 0; i < dysymtab->nlocrel; i++) {
    const struct relocation_info *r = &relocs[i];
    /* Only ARM64_RELOC_UNSIGNED is a standalone absolute pointer.  The
     * other ARM64 relocation kinds participate in instruction/addend pairs
     * and cannot be represented by a single KC rebase slot. */
    if (r->r_extern || r->r_pcrel || r->r_length != RL_QUAD ||
        r->r_type != ARM64_RELOC_UNSIGNED)
      continue;
    /* ARM64 local relocation addresses are offsets from the image's first
     * segment VM address, including split-segment kernels. */
    /* MachOAnalyzer applies the signed relocation offset relative to the
     * first segment for static executables and filesets. */
    uint64_t reloc_vmaddr = segs[first]->vmaddr + (int32_t)r->r_address;
    uint64_t fileoff = UINT64_MAX;
    for (size_t si = 0; si < nsegs; si++) {
      if (segs[si]->filesize == 0 ||
          reloc_vmaddr < segs[si]->vmaddr ||
          reloc_vmaddr + 8 > segs[si]->vmaddr + segs[si]->filesize)
        continue;
      /* ARM64 local relocations also describe address materialization in
       * executable text. Those are instruction/data relocations, not pointer
       * slots, and encoding them as KC chained pointers overwrites code. Use
       * initprot as the authoritative test: a KC may rename or merge text
       * segments, so filtering only by the conventional __TEXT* names is not
       * sufficient. */
      if ((segs[si]->initprot & VM_PROT_EXECUTE) != 0 ||
          !strncmp(segs[si]->segname, "__TEXT", 6))
        break;
      fileoff = segs[si]->fileoff + (reloc_vmaddr - segs[si]->vmaddr);
      if (fileoff + 8 > data_size)
        break;
      if (counts[si] == caps[si]) {
        uint32_t next = caps[si] ? caps[si] * 2 : 64;
        FixupSite *grown = realloc(sites[si], next * sizeof(*grown));
        if (!grown) goto fail;
        sites[si] = grown;
        caps[si] = next;
      }
      sites[si][counts[si]++] = (FixupSite){fileoff, (uint32_t)si};
      break;
    }
  }

  /* One chain per page is always sufficient: any two 8-byte-aligned slots on
   * the same 0x1000 page are at most 0xff8 apart, well within the 12-bit next
   * field's 0x3ffc reach.  So each segment needs only its per-page start table
   * (dyld_chained_starts_in_segment) with no auxiliary chain_starts array. */
  uint32_t starts_size = sizeof(uint32_t) + (uint32_t)nsegs * sizeof(uint32_t);
  uint32_t total_sites = 0;
  for (size_t si = 0; si < nsegs; si++) {
    if (!counts[si]) continue;
    total_sites += counts[si];
    qsort(sites[si], counts[si], sizeof(*sites[si]), fixup_site_compare);
    uint64_t pages = (segs[si]->vmsize + 0xfff) / 0x1000;
    if (pages > UINT16_MAX) goto fail;
    starts_size += 22 + (uint32_t)pages * sizeof(uint16_t);
  }
  fprintf(stderr, "fileset: local reloc sites=%u starts_size=0x%x\n",
          total_sites, starts_size);
  for (size_t si = 0; si < nsegs; si++)
    if (counts[si])
      fprintf(stderr, "fileset: fixup seg[%zu] %s count=%u\n",
          si, segs[si]->segname, counts[si]);
  uint32_t blob_size = (uint32_t)sizeof(struct dyld_chained_fixups_header) +
      starts_size;
  uint8_t *blob = calloc(1, blob_size);
  if (!blob) goto fail;

  struct dyld_chained_fixups_header *fh =
      (struct dyld_chained_fixups_header *)blob;
  fh->fixups_version = 0;
  fh->starts_offset = sizeof(*fh);
  fh->imports_offset = blob_size;
  fh->symbols_offset = blob_size;
  fh->imports_count = 0;
  fh->imports_format = 1;
  fh->symbols_format = 0;

  uint8_t *sp = blob + sizeof(*fh);
  *(uint32_t *)sp = (uint32_t)nsegs;
  uint32_t *offsets = (uint32_t *)(sp + sizeof(uint32_t));
  uint8_t *info = sp + sizeof(uint32_t) + (uint32_t)nsegs * sizeof(uint32_t);
  for (size_t si = 0; si < nsegs; si++) {
    if (!counts[si]) continue;
    offsets[si] = (uint32_t)(info - sp);
    uint32_t pages = (uint32_t)((segs[si]->vmsize + 0xfff) / 0x1000);
    /* dyld_chained_starts_in_segment: page_start[] begins at offset 22
     * (4+2+2+8+4+2), immediately after page_count. */
    uint32_t info_size = 22 + pages * sizeof(uint16_t);
    *(uint32_t *)(info + 0) = info_size;
    *(uint16_t *)(info + 4) = 0x1000;
    *(uint16_t *)(info + 6) = DYLD_CHAINED_PTR_64_KERNEL_CACHE;
    *(uint64_t *)(info + 8) = segs[si]->vmaddr - base_vmaddr;
    *(uint32_t *)(info + 16) = 0;
    *(uint16_t *)(info + 20) = (uint16_t)pages;
    uint16_t *page_start = (uint16_t *)(info + 22);
    for (uint32_t pi = 0; pi < pages; pi++) page_start[pi] = DYLD_CHAINED_PTR_START_NONE;

    /* Thread every valid site on a page into a single chain, in ascending
     * order, and encode each slot's KC-relative target.  page_start records
     * the first member; each non-last member carries the 4-byte-scaled delta
     * to the next in its high next field. */
    uint32_t prev_fileoff = 0;
    uint32_t open_page = UINT32_MAX;
    for (uint32_t j = 0; j < counts[si]; j++) {
      uint64_t off = sites[si][j].fileoff - segs[si]->fileoff;
      uint32_t page = (uint32_t)(off / 0x1000);
      if (page >= pages || (off & 7) != 0)
        continue;
      if (sites[si][j].fileoff + 8 > data_size)
        continue;
      uint8_t *loc = data + sites[si][j].fileoff;
      uint64_t target = *(uint64_t *)loc;
      /* A classic local relocation may describe a NULL pointer.  Chained
       * fixups have no NULL target encoding: target offset zero is resolved
       * to the KC base, so leaving this slot in a chain silently turns NULL
       * object pointers into valid kernel addresses. */
      if (target == 0)
        continue;
      /* dyld writes the raw kernel-cache target offset and leaves all chain
       * metadata clear until it links the predecessor. Do not mask an
       * out-of-range pointer into a plausible but invalid KC address. */
      if (target < base_vmaddr || target - base_vmaddr >= (1ULL << 30)) {
        fprintf(stderr, "fileset: KC target outside base range at fileoff=0x%llx target=0x%llx base=0x%llx\n",
            (unsigned long long)sites[si][j].fileoff,
            (unsigned long long)target, (unsigned long long)base_vmaddr);
        continue;
      }
      *(uint64_t *)loc = target - base_vmaddr;

      if (page != open_page) {
        page_start[page] = (uint16_t)(off & 0xfff);
        open_page = page;
      } else {
        uint64_t delta = (sites[si][j].fileoff - prev_fileoff) / 4;
        uint64_t previous = *(uint64_t *)(data + prev_fileoff);
        previous &= ~(0xfffULL << 51);
        previous |= (delta & 0xfffULL) << 51;
        *(uint64_t *)(data + prev_fileoff) = previous;
      }
      prev_fileoff = (uint32_t)sites[si][j].fileoff;
    }
    info += info_size;
  }
  for (size_t si = 0; si < nsegs; si++) free(sites[si]);
  free(sites); free(counts); free(caps);
  *out_blob = blob;
  *out_size = blob_size;
  return 0;
fail:
  if (sites) for (size_t si = 0; si < nsegs; si++) free(sites[si]);
  free(sites); free(counts); free(caps);
  return -1;
}

// Collect the input kernel's LC_SEGMENT_64 commands.
typedef struct {
  const struct segment_command_64 *lc;  // pointer into kernel_data
} SegRef;

// Earlier revisions of this tool appended a separate synthetic "__KCHDR"
// segment (its own mach_header_64 + load commands) after the whole image,
// carrying the MH_FILESET wrapper. That broke XNU's kernel_collection_slide()
// (osfmk/mach/dyld_kernel_fixups.h): it derives its own internal "slide" as
// (uintptr_t)kc_mh - textVMAddr, where textVMAddr comes from kc_mh's own
// copy of the __TEXT segment command. Real Apple KCs have their MH_FILESET
// header co-located with the image's own __TEXT (so that delta is always
// the genuine KASLR slide, 0 here); our appended-at-the-end __KCHDR made it
// a huge bogus value, and every subsequent address computation (including
// the chained-fixups header address) landed in unmapped memory.
//
// Fix: convert the kernel's OWN mach_header_64 in place into the MH_FILESET
// header, append LC_FILESET_ENTRY (kernel + each real kext) and
// LC_DYLD_CHAINED_FIXUPS directly onto its EXISTING load command list,
// reusing its EXISTING LC_SEGMENT_64 entries verbatim (no separate segment
// copies needed). This makes kc_mh and textVMAddr the literal same object,
// so that internal slide is trivially 0 by construction, no address
// arithmetic to get wrong. Apple kernels reserve generous zero padding
// between the end of their load commands and the first real segment's file
// content specifically to allow this kind of in-place growth.
int fileset_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size)
{
  uint64_t arm64_entry = 0;
  if (kernel_size >= sizeof(struct mach_header_64)) {
    const struct mach_header_64 *input_mh =
        (const struct mach_header_64 *)kernel_data;
    if (input_mh->magic == MH_MAGIC_64 && input_mh->cputype == CPU_TYPE_ARM64)
      arm64_entry = kernel_arm64_start(kernel_data, kernel_size, input_mh);
  }

  // If there are kexts, first produce a classic prelinked image (kexts placed
  // in __PRELINK_TEXT, _PrelinkInfoDictionary in __PRELINK_INFO). Then wrap it
  // as a fileset. This reuses all of prelink.c's kext placement + plist logic;
  // the only fileset-specific work is the MH_FILESET wrapper below.
  uint8_t *base_data = (uint8_t *)kernel_data;
  size_t   base_size = kernel_size;
  int      base_owned = 0;
  if (num_kexts > 0) {
    if (prelink_assemble(kernel_data, kernel_size, kexts, num_kexts,
                         &base_data, &base_size) != 0) {
      fprintf(stderr, "fileset: prelink_assemble failed\n");
      return -1;
    }
    base_owned = 1;
  }

  const struct mach_header_64 *mh = (const struct mach_header_64 *)base_data;
  /* The collection-layout rewrites below (republishing the prelink payload as
   * __TEXT_EXEC/__KEXT_DATA, zeroing the prelink commands, merging
   * __LASTDATA_CONST into __DATA_CONST, extending __LINKEDIT over the prelink
   * XML) all exist to satisfy arm_vm_init. i386_init has no equivalent
   * requirements and XNU's x86 path still reads the payload out of the
   * original prelink segments, so they must not be applied there. */
  const int kc_is_arm64 =
      (mh->magic == MH_MAGIC_64 && mh->cputype == CPU_TYPE_ARM64);
  if (mh->magic != MH_MAGIC_64) {
    fprintf(stderr, "fileset: kernel not MH_MAGIC_64 (0x%x)\n", mh->magic);
    if (base_owned)
      free(base_data);
    return -1;
  }

  const struct segment_command_64 *segs[64];
  size_t nsegs = 0;
  uint64_t kernel_vm_end = 0;
  uint64_t first_seg_vmaddr = 0;
  const struct segment_command_64 *prelink_data = NULL;
  const struct segment_command_64 *prelink_info = NULL;
  const struct segment_command_64 *prelink_text = NULL;
  const struct segment_command_64 *data_seg = NULL;
  const struct segment_command_64 *text_exec_seg = NULL;
  const struct segment_command_64 *linkedit_seg = NULL;
  struct segment_command_64 *data_const = NULL;
  struct segment_command_64 *last_data_const = NULL;
  int has_chained_fixups = 0;
  {
    const uint8_t *lcp = base_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc =
            (const struct segment_command_64 *)lcp;
        if (nsegs < 64)
          segs[nsegs++] = sc;
        if (first_seg_vmaddr == 0 && sc->fileoff == 0)
          first_seg_vmaddr = sc->vmaddr;
        if (sc->vmsize > 0) {
          uint64_t end = sc->vmaddr + sc->vmsize;
          if (end > kernel_vm_end) kernel_vm_end = end;
        }
        if (!memcmp(sc->segname, "__PRELINK_INFO", 14))
          prelink_info = sc;
        if (!memcmp(sc->segname, "__PRELINK_DATA", 14))
          prelink_data = sc;
        if (!strcmp(sc->segname, "__DATA"))
          data_seg = sc;
        if (!strcmp(sc->segname, "__TEXT_EXEC"))
          text_exec_seg = sc;
        if (!memcmp(sc->segname, "__LINKEDIT", 11))
          linkedit_seg = sc;
        if (!memcmp(sc->segname, "__PRELINK_TEXT", 14))
          prelink_text = sc;
        if (!memcmp(sc->segname, "__DATA_CONST", 12))
          data_const = (struct segment_command_64 *)sc;
        if (!memcmp(sc->segname, "__LASTDATA_CONST", 16))
          last_data_const = (struct segment_command_64 *)sc;
      }
      if (lc->cmd == LC_DYLD_CHAINED_FIXUPS)
        has_chained_fixups = 1;
      lcp += lc->cmdsize;
    }
  }

  if (base_owned && prelink_text) {
    uint64_t pt_vmaddr  = prelink_text->vmaddr;
    uint64_t pt_fileoff = prelink_text->fileoff;
    for (size_t i = 0; i < num_kexts; i++) {
      if (kexts[i].load_vmaddr < pt_vmaddr) continue;
      size_t koff = pt_fileoff + (kexts[i].load_vmaddr - pt_vmaddr);
      if (koff + sizeof(struct mach_header_64) > base_size) continue;
      struct mach_header_64 *kmh = (struct mach_header_64 *)(base_data + koff);
      if (kmh->magic == MH_MAGIC_64)
        kmh->flags |= MH_DYLIB_IN_CACHE;
    }
  }
  if (first_seg_vmaddr == 0) {
    // fall back to the lowest segment vmaddr
    for (size_t i = 0; i < nsegs; i++)
      if (first_seg_vmaddr == 0 || segs[i]->vmaddr < first_seg_vmaddr)
        first_seg_vmaddr = segs[i]->vmaddr;
  }
  (void)prelink_info; (void)kexts; (void)num_kexts;

  /* XNU's fileset VM setup treats the kernel LASTDATA_CONST tail as part of
   * the collection DATA_CONST range. The linker emits the two adjacent
   * segments separately, so make the collection extent explicit here. */
  if (data_const && last_data_const &&
      data_const->vmaddr <= last_data_const->vmaddr) {
    uint64_t data_end = data_const->vmaddr + data_const->vmsize;
    uint64_t last_end = last_data_const->vmaddr + last_data_const->vmsize;
    if (last_end > data_end) {
      data_const->vmsize = last_end - data_const->vmaddr;
      uint64_t file_end = last_data_const->fileoff + last_data_const->filesize;
      uint64_t data_file_end = data_const->fileoff + data_const->filesize;
      if (file_end > data_file_end &&
          file_end - data_const->fileoff <= data_const->vmsize)
        data_const->filesize = file_end - data_const->fileoff;
    }
  }

  if (base_owned) { // only when we produced a prelinked base (kexts present)
    uint64_t prelink_end = 0;
    struct segment_command_64 *linkedit = NULL;
    for (size_t i = 0; i < nsegs; i++) {
      if (!memcmp(segs[i]->segname, "__PRELINK_TEXT", 14) ||
          !memcmp(segs[i]->segname, "__PRELINK_INFO", 14)) {
        uint64_t e = segs[i]->vmaddr + segs[i]->vmsize;
        if (e > prelink_end) prelink_end = e;
      }
      if (!memcmp(segs[i]->segname, "__LINKEDIT", 11))
        linkedit = (struct segment_command_64 *)segs[i]; // base_data is mutable
    }
    if (linkedit && prelink_end && linkedit->vmaddr < prelink_end) {
      uint64_t new_va = ALIGN_UP(prelink_end, PAGE);
      fprintf(stderr, "fileset: moving __LINKEDIT vmaddr 0x%llx -> 0x%llx (after __PRELINK_TEXT)\n",
              (unsigned long long)linkedit->vmaddr, (unsigned long long)new_va);
      linkedit->vmaddr = new_va;
      // recompute kernel_vm_end
      kernel_vm_end = 0;
      for (size_t i = 0; i < nsegs; i++)
        if (segs[i]->vmsize > 0 && segs[i]->vmaddr + segs[i]->vmsize > kernel_vm_end)
          kernel_vm_end = segs[i]->vmaddr + segs[i]->vmsize;
    }
  }

  fprintf(stderr, "fileset: kernel hdr vmaddr=0x%llx vm_end=0x%llx segs=%zu\n",
          (unsigned long long)first_seg_vmaddr,
          (unsigned long long)kernel_vm_end, nsegs);

  static const char kernel_entry_id[] = "com.apple.kernel";
  uint32_t fe_idlen = (uint32_t)sizeof(kernel_entry_id); // incl NUL
  uint32_t fe_cmdsize = (uint32_t)ALIGN_UP(sizeof(struct fileset_entry_command) + fe_idlen, 8);

  // Per-kext fileset entries: one LC_FILESET_ENTRY per kext,
  // entry_id = bundle id, vmaddr = kext load address, fileoff = its offset
  // within the KC file.
  uint64_t pt_vmaddr  = prelink_text ? prelink_text->vmaddr  : 0;
  uint64_t pt_fileoff = prelink_text ? prelink_text->fileoff : 0;
  uint32_t kext_fe_cmdsize[64];
  uint32_t kext_fe_total = 0;
  size_t   n_kext_fe = (prelink_text ? num_kexts : 0);
  if (n_kext_fe > 64) n_kext_fe = 64;
  for (size_t i = 0; i < n_kext_fe; i++) {
    if (kexts[i].codeless) { kext_fe_cmdsize[i] = 0; continue; }  // no segments
    uint32_t idlen = (uint32_t)strlen(kexts[i].bundle_id) + 1;
    uint32_t cs = (uint32_t)ALIGN_UP(sizeof(struct fileset_entry_command) + idlen, 8);
    kext_fe_cmdsize[i] = cs;
    kext_fe_total += cs;
  }

  uint32_t chained_cmdsize = has_chained_fixups ? 0 :
      (uint32_t)sizeof(struct linkedit_data_command);

  uint32_t n_real_fe = 0; // non-codeless kext fileset entries actually emitted
  for (size_t i = 0; i < n_kext_fe; i++)
    if (kext_fe_cmdsize[i]) n_real_fe++;

  /* XNU's kernel entry expects the three PRELINK commands to exist, but
   * arm_vm_init requires them to describe an empty kernel-side prelink area.
   * Keep those original commands as zero-sized placeholders and append
   * copies under KC-private names for the collection payload.
   *
   * This is an arm64-only requirement. i386_init has no equivalent rule: on
   * x86 XNU still expects the payload to live in __PRELINK_TEXT/__PRELINK_INFO
   * at their real sizes, and OSKext::start() resolves a kext's start function
   * through them. Republishing the payload as __TEXT_EXEC/__KEXT_DATA and
   * zeroing the prelink commands there makes every kext fail to start with
   * "memory region containing module start function is not executable". */
  struct {
    uint8_t *data;
    uint32_t size;
    const char *name;
  } payload_segs[2 + 64 * 8];
  size_t payload_seg_count = 0;
  uint64_t data_end_vmaddr = data_seg ? data_seg->vmaddr + data_seg->vmsize : 0;
  uint64_t text_exec_vmaddr = text_exec_seg ? text_exec_seg->vmaddr : 0;
  const struct segment_command_64 *payload_sources[2] = {
    prelink_data, prelink_text
  };
  const char *payload_names[2] = {
    "__DATA", "__TEXT_EXEC"
  };
  for (size_t i = 0; kc_is_arm64 && i < 2; i++) {
    if (!payload_sources[i]) continue;
    payload_segs[payload_seg_count].size = payload_sources[i]->cmdsize;
    payload_segs[payload_seg_count].data = malloc(payload_sources[i]->cmdsize);
    if (!payload_segs[payload_seg_count].data) {
      for (size_t j = 0; j < payload_seg_count; j++)
        free(payload_segs[j].data);
      if (base_owned) free(base_data);
      return -1;
    }
    memcpy(payload_segs[payload_seg_count].data, payload_sources[i],
           payload_sources[i]->cmdsize);
    payload_segs[payload_seg_count].name = payload_names[i];
    payload_seg_count++;
  }

  /* prelink_assemble stores each complete linked kext in the PRELINK_TEXT
   * file range. The aggregate KC text command must not own the kext data
   * pages, so publish those original non-executable segments separately with
   * the same file-to-VM delta. */
  for (size_t j = 0; kc_is_arm64 && j < num_kexts; j++) {
    if (kexts[j].codeless || !kexts[j].linked_data ||
        kexts[j].linked_size < sizeof(struct mach_header_64))
      continue;
    const uint8_t *kp = kexts[j].linked_data + sizeof(struct mach_header_64);
    const uint8_t *kend = kexts[j].linked_data + kexts[j].linked_size;
    const struct mach_header_64 *kmh =
        (const struct mach_header_64 *)kexts[j].linked_data;
    for (uint32_t ci = 0; ci < kmh->ncmds; ci++) {
      if (kp + sizeof(struct load_command) > kend)
        break;
      const struct load_command *lc = (const struct load_command *)kp;
      if (lc->cmdsize < sizeof(*lc) || kp + lc->cmdsize > kend)
        break;
      if (lc->cmd == LC_SEGMENT_64 &&
          lc->cmdsize >= sizeof(struct segment_command_64)) {
        const struct segment_command_64 *ksc =
            (const struct segment_command_64 *)kp;
        if (ksc->filesize != 0 &&
            (ksc->initprot & VM_PROT_EXECUTE) == 0 &&
            strncmp(ksc->segname, "__LINKEDIT", 16) != 0 &&
            payload_seg_count < sizeof(payload_segs) / sizeof(payload_segs[0])) {
          struct segment_command_64 *sc = calloc(1, sizeof(*sc));
          if (!sc) {
            for (size_t n = 0; n < payload_seg_count; n++)
              free(payload_segs[n].data);
            if (base_owned) free(base_data);
            return -1;
          }
          *sc = *ksc;
          sc->cmdsize = sizeof(*sc);
          sc->nsects = 0;
          sc->vmaddr = kexts[j].load_vmaddr + ksc->vmaddr -
              kexts[j].load_vmaddr;
          sc->fileoff = pt_fileoff +
              (kexts[j].load_vmaddr - pt_vmaddr) + ksc->fileoff;
          payload_segs[payload_seg_count].data = (uint8_t *)sc;
          payload_segs[payload_seg_count].size = sizeof(*sc);
          payload_segs[payload_seg_count].name = "__KEXT_DATA";
          payload_seg_count++;
        }
      }
      kp += lc->cmdsize;
    }
  }

  /* The prelink segment's original vmsize can stop before the final page
   * occupied by a kext's kmod_info/data.  The fileset entries use the
   * placement metadata as the authoritative extent, so make the collection
   * payload cover every placed kext page. */
  for (size_t i = 0; i < payload_seg_count; i++) {
    if (strcmp(payload_segs[i].name, "__TEXT_EXEC") != 0)
      continue;
    struct segment_command_64 *sc =
        (struct segment_command_64 *)payload_segs[i].data;
    uint64_t payload_end = sc->vmaddr + sc->vmsize;
    for (size_t j = 0; j < num_kexts; j++) {
      /* Only executable kext segments belong in the KC text payload. The
       * complete kext extent includes __DATA_CONST/__DATA; extending
       * __TEXT_EXEC over that range overlays literals and vtables. */
      uint64_t kext_extent = macho_exec_vm_end(kexts[j].linked_data,
          kexts[j].linked_size);
      uint64_t kext_end = ALIGN_UP(kext_extent, 0x1000);
      if (kext_end > payload_end)
        payload_end = kext_end;
    }
    if (payload_end > sc->vmaddr) {
      uint64_t extent = ALIGN_UP(payload_end - sc->vmaddr, 0x1000);
      if (extent > sc->vmsize)
        sc->vmsize = extent;
      if (extent > sc->filesize)
        sc->filesize = extent;
    }
  }

  // New commands appended to the kernel's EXISTING load command list: 1
  // LC_FILESET_ENTRY (kernel, self-referential) + one per real kext + 1
  // LC_DYLD_CHAINED_FIXUPS, plus the mapped payload segment copies.
  uint32_t new_ncmds = 1 + n_real_fe + (has_chained_fixups ? 0 : 1) +
      (uint32_t)payload_seg_count;
  uint32_t payload_cmds_size = 0;
  for (size_t i = 0; i < payload_seg_count; i++)
    payload_cmds_size += payload_segs[i].size;
  uint32_t new_cmds_size = fe_cmdsize + kext_fe_total + chained_cmdsize +
      payload_cmds_size;

  uint8_t *fixups_blob = NULL;
  uint32_t fixups_size = 0;
  if (!has_chained_fixups) {
    if (mh->cputype == CPU_TYPE_ARM64 &&
        build_kernel_cache_fixups(base_data, base_size, mh, segs, nsegs,
            first_seg_vmaddr, &fixups_blob, &fixups_size) != 0) {
      fprintf(stderr, "fileset: ARM64 chained fixup generation failed\n");
      fixups_size = 0;
    }
    if (!fixups_blob) {
      uint32_t fixups_hdr_size = (uint32_t)sizeof(struct dyld_chained_fixups_header);
      fixups_size = fixups_hdr_size + 4; // starts_in_image.seg_count == 0
    }
  }

  size_t hdr_cmds_end = sizeof(*mh) + mh->sizeofcmds;
  size_t new_cmds_off = hdr_cmds_end;                                // where the new LCs start

  // The chained-fixups DATA blob must live inside __LINKEDIT's own file
  // range: kernel_collection_slide() computes its address as linkeditVMAddr
  // + (dataoff - linkeditFileOffset), which only lands correctly if dataoff
  // shares __LINKEDIT's fileoff<->vmaddr delta, true for any byte actually
  // inside __LINKEDIT, false everywhere else (this is what broke the
  // earlier "put it in the header padding" attempt: __TEXT's delta differs
  // from __LINKEDIT's). We reuse the page-alignment slack Apple's own
  // toolchain already leaves between __LINKEDIT's real content and the next
  // segment's file data, rather than shifting the whole file.
  size_t linkedit_off = 0, linkedit_fileoff = 0, linkedit_filesize = 0;
  uint64_t linkedit_vmsize = 0;
  uint64_t prelink_info_mapped_vmaddr = 0;
  uint64_t prelink_info_fileoff = 0;
  uint64_t prelink_info_filesize = 0;
  uint64_t next_seg_fileoff = base_size;
  {
    const uint8_t *lcp = base_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc =
            (const struct segment_command_64 *)lcp;
        if (!memcmp(sc->segname, "__LINKEDIT", 11)) {
          linkedit_off = (size_t)(lcp - base_data);
          linkedit_fileoff = sc->fileoff;
          linkedit_filesize = sc->filesize;
          linkedit_vmsize = sc->vmsize;
        }
      }
      lcp += lc->cmdsize;
    }
    if (!linkedit_off) {
      fprintf(stderr, "fileset: no __LINKEDIT segment found\n");
      if (base_owned) free(base_data);
      return -1;
    }
    // Smallest fileoff of any segment starting after __LINKEDIT's own
    // content, the fixups blob must fit before it.
    lcp = base_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc =
            (const struct segment_command_64 *)lcp;
        if (sc->filesize > 0 && sc->fileoff >= linkedit_fileoff + linkedit_filesize &&
            sc->fileoff < next_seg_fileoff)
          next_seg_fileoff = sc->fileoff;
      }
      lcp += lc->cmdsize;
    }
  }
  if (linkedit_seg && prelink_info) {
    prelink_info_fileoff = prelink_info->fileoff;
    prelink_info_filesize = prelink_info->filesize;
    prelink_info_mapped_vmaddr = linkedit_seg->vmaddr +
        (prelink_info->fileoff - linkedit_seg->fileoff);
  }
  size_t fixups_off = ALIGN_UP(linkedit_fileoff + linkedit_filesize, 8);
  if (fixups_off + fixups_size > next_seg_fileoff) {
    // The KC fixup payload belongs to __LINKEDIT's address space, but it does
    // not have to fit in the input file's existing alignment hole. Appending
    // it after the complete image is safe when the segment's file range is
    // extended along with its vm range, and avoids shifting loaded segments.
    fixups_off = ALIGN_UP(base_size, 8);
    fprintf(stderr,
            "fileset: extending __LINKEDIT for chained fixups at fileoff=0x%zx\n",
            fixups_off);
  }

  // First byte of real segment data (limits header growth, everything up
  // to here must be padding, or we'd corrupt real segment content).
  uint64_t body_off = base_size;
  {
    const uint8_t *lcp = base_data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
      const struct load_command *lc = (const struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *sc =
            (const struct segment_command_64 *)lcp;
        if (sc->filesize > 0 && sc->fileoff > 0 && sc->fileoff < body_off)
          body_off = sc->fileoff;
      }
      lcp += lc->cmdsize;
    }
  }
  if (new_cmds_off + new_cmds_size > body_off) {
    fprintf(stderr,
            "fileset: no header room to grow in place (need up to 0x%zx, "
            "first real segment data starts at 0x%llx)\n",
            new_cmds_off + new_cmds_size, (unsigned long long)body_off);
    if (base_owned) free(base_data);
    return -1;
  }

  size_t out_len = base_size;
  if (fixups_off + fixups_size > out_len)
    out_len = fixups_off + fixups_size;
  fprintf(stderr, "fileset: output size=0x%zx fixups size=0x%x\n",
          out_len, fixups_size);
    uint8_t *out = calloc(1, out_len);
  if (!out) {
    for (size_t i = 0; i < payload_seg_count; i++) free(payload_segs[i].data);
    if (base_owned) free(base_data);
    return -1;
  }
  memcpy(out, base_data, base_size);
  if (base_owned)
    free(base_data);

  struct mach_header_64 *omh = (struct mach_header_64 *)out;

  if (omh->cputype == CPU_TYPE_ARM64)
    kernel_arm64_set_entry(out, out_len, omh, arm64_entry);

  /* Preserve non-null, zero-sized PRELINK placeholders for the embedded
   * kernel entry. The real payload is represented by the appended KC-private
   * segment commands below. */
  {
    uint8_t *lcp = out + sizeof(*omh);
    for (uint32_t i = 0; i < omh->ncmds; i++) {
      struct load_command *lc = (struct load_command *)lcp;
      if (lc->cmd == LC_SEGMENT_64) {
        struct segment_command_64 *sc = (struct segment_command_64 *)lcp;
        if (!strcmp(sc->segname, "__TEXT") && text_exec_vmaddr > sc->vmaddr &&
            text_exec_vmaddr - sc->vmaddr > sc->vmsize)
          sc->vmsize = text_exec_vmaddr - sc->vmaddr;
        if (!memcmp(sc->segname, "__PLK_DATA_CONST", 16) ||
            !memcmp(sc->segname, "__PLK_TEXT_EXEC", 15)) {
          /* These commands belong to the embedded kernel.  The collection
           * payload is represented by the KC-level copies below; leaving a
           * one-page PLK_DATA_CONST here violates XNU's paired-segment
           * invariant before VM initialization can begin. */
          sc->filesize = 0;
          sc->vmsize = 0;
        }
        /* Zeroing the prelink commands is part of the same arm64-only
         * republish: on x86 the payload stays in them (see kc_is_arm64). */
        if (kc_is_arm64 && !memcmp(sc->segname, "__PRELINK_DATA", 14)) {
          uint64_t original_vmaddr = sc->vmaddr;
          struct section_64 *sects = (struct section_64 *)(sc + 1);
          for (uint32_t s = 0; s < sc->nsects; s++) {
            if (sects[s].offset >= sc->fileoff)
              sects[s].addr = original_vmaddr +
                  (sects[s].offset - sc->fileoff);
          }
          sc->filesize = 0;
          sc->vmsize = 0;
          if (data_end_vmaddr)
            sc->vmaddr = data_end_vmaddr;
        } else if (kc_is_arm64 &&
                   (!memcmp(sc->segname, "__PRELINK_TEXT", 14) ||
                    !memcmp(sc->segname, "__PRELINK_INFO", 14))) {
          struct section_64 *sects = (struct section_64 *)(sc + 1);
          uint64_t mapped_vmaddr = sc->vmaddr;
          if (!memcmp(sc->segname, "__PRELINK_INFO", 14) &&
              prelink_info_mapped_vmaddr)
            mapped_vmaddr = prelink_info_mapped_vmaddr;
          for (uint32_t s = 0; s < sc->nsects; s++)
            if (sects[s].offset >= sc->fileoff)
              sects[s].addr = mapped_vmaddr +
                  (sects[s].offset - sc->fileoff);
          sc->filesize = 0;
          sc->vmsize = 0;
          sc->vmaddr = mapped_vmaddr;
        }
      }
      lcp += lc->cmdsize;
    }
  }

  omh->filetype = MH_FILESET;
  omh->flags |= MH_DYLIB_IN_CACHE; // kernel_mach_header_is_in_fileset() only checks this flag
  omh->ncmds += new_ncmds;
  omh->sizeofcmds += new_cmds_size;

  /* The embedded kernel's PLK segments are placeholders, not the KC
   * payload.  Normalize them after appending every load command so no later
   * header rewrite can leave one half of XNU's paired PLK range non-empty. */
  {
    uint8_t *scan = out + sizeof(*omh);
    for (uint32_t i = 0; i < omh->ncmds; i++) {
      struct load_command *lc = (struct load_command *)scan;
      if (lc->cmd == LC_SEGMENT_64) {
        struct segment_command_64 *sc = (struct segment_command_64 *)scan;
        if (!memcmp(sc->segname, "__PLK_DATA_CONST", 16) ||
            !memcmp(sc->segname, "__PLK_TEXT_EXEC", 15)) {
          fprintf(stderr, "fileset: clearing %.*s vm=0x%llx vmsize=0x%llx filesize=0x%llx\n",
                  16, sc->segname, (unsigned long long)sc->vmaddr,
                  (unsigned long long)sc->vmsize,
                  (unsigned long long)sc->filesize);
          sc->filesize = 0;
          sc->vmsize = 0;
        }
      }
      scan += lc->cmdsize;
    }
  }

  // Keep the prelink XML reachable through the KC's linkedit file-to-VM
  // mapping. The kernel-side PRELINK_INFO command is only a placeholder, but
  // IOKit still parses the bytes produced by prelink_assemble().
  {
    struct segment_command_64 *le = (struct segment_command_64 *)(out + linkedit_off);
    uint64_t required_end = fixups_off + fixups_size;
    if (prelink_info_filesize) {
      uint64_t info_end = prelink_info_fileoff + prelink_info_filesize;
      if (info_end > required_end)
        required_end = info_end;
    }
    uint64_t new_filesize = required_end - linkedit_fileoff;
    uint64_t grew = new_filesize > linkedit_filesize ?
        new_filesize - linkedit_filesize : 0;
    le->filesize = new_filesize;
    uint64_t new_vmsize = linkedit_vmsize + grew;
    if (new_vmsize < new_filesize)
      new_vmsize = new_filesize;
    le->vmsize = new_vmsize;
  }

  uint8_t *p = out + new_cmds_off;

  // LC_FILESET_ENTRY for the kernel itself: self-referential, since kc_mh
  // and the kernel's own header are now literally the same object.
  struct fileset_entry_command *fe = (struct fileset_entry_command *)p;
  fe->cmd = LC_FILESET_ENTRY;
  fe->cmdsize = fe_cmdsize;
  fe->vmaddr = first_seg_vmaddr;
  fe->fileoff = 0;
  fe->entry_id = (uint32_t)sizeof(struct fileset_entry_command);
  memcpy(p + fe->entry_id, kernel_entry_id, fe_idlen);
  p += fe_cmdsize;

  // LC_FILESET_ENTRY for each real (non-codeless) kext.
  for (size_t i = 0; i < n_kext_fe; i++) {
    if (!kext_fe_cmdsize[i]) continue; // codeless: no fileset entry
    struct fileset_entry_command *ke = (struct fileset_entry_command *)p;
    uint32_t idlen = (uint32_t)strlen(kexts[i].bundle_id) + 1;
    ke->cmd = LC_FILESET_ENTRY;
    ke->cmdsize = kext_fe_cmdsize[i];
    ke->vmaddr = kexts[i].load_vmaddr;
    ke->fileoff = pt_fileoff + (kexts[i].load_vmaddr - pt_vmaddr);
    ke->entry_id = (uint32_t)sizeof(struct fileset_entry_command);
    ke->reserved = 0;
    memcpy(p + ke->entry_id, kexts[i].bundle_id, idlen);
    p += kext_fe_cmdsize[i];
  }

  for (size_t i = 0; i < payload_seg_count; i++) {
    memcpy(p, payload_segs[i].data, payload_segs[i].size);
    struct segment_command_64 *sc = (struct segment_command_64 *)p;
    memset(sc->segname, 0, sizeof(sc->segname));
    memcpy(sc->segname, payload_segs[i].name,
           strlen(payload_segs[i].name));
    p += payload_segs[i].size;
    free(payload_segs[i].data);
    payload_segs[i].data = NULL;
  }

  // Keep the kernel's existing chained-fixups command. XNU selects the last
  // LC_DYLD_CHAINED_FIXUPS command it sees, so appending an empty command
  // here would silently disable every real rebase in the kernel image.
  if (!has_chained_fixups) {
    struct linkedit_data_command *cf = (struct linkedit_data_command *)p;
    cf->cmd = LC_DYLD_CHAINED_FIXUPS;
    cf->cmdsize = chained_cmdsize;
    cf->dataoff = (uint32_t)fixups_off;
    cf->datasize = fixups_size;
  }

  if (!has_chained_fixups) {
    if (fixups_blob) {
      memcpy(out + fixups_off, fixups_blob, fixups_size);
      free(fixups_blob);
    } else {
      uint32_t fixups_hdr_size = (uint32_t)sizeof(struct dyld_chained_fixups_header);
      struct dyld_chained_fixups_header *fh =
          (struct dyld_chained_fixups_header *)(out + fixups_off);
      fh->fixups_version = 0;
      fh->starts_offset = fixups_hdr_size;
      fh->imports_offset = fixups_hdr_size + 4;
      fh->symbols_offset = fixups_hdr_size + 4;
      fh->imports_count = 0;
      fh->imports_format = 1;
      fh->symbols_format = 0;
      *(uint32_t *)(out + fixups_off + fixups_hdr_size) = 0;
    }
  }

  fprintf(stderr,
          "fileset: converted kernel header in place: vmaddr=0x%llx "
          "ncmds=%u sizeofcmds=%u (grew by %u bytes), fixups at fileoff=0x%zx\n",
          (unsigned long long)first_seg_vmaddr, omh->ncmds, omh->sizeofcmds,
          new_cmds_size, fixups_off);

  *out_data = out;
  *out_size = out_len;
  return 0;
}
