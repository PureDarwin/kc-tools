#include "prelink.h"
#include "plist.h"
#include "macho_fmt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PAGE 0x1000ULL
#define ALIGN_UP(x, a) (((uint64_t)(x) + ((uint64_t)(a) - 1)) & ~((uint64_t)(a) - 1))

// The kernel collection's __KCHDR segment name (our private convention; the
// loader looks for this to locate the top-level MH_FILESET header).
#define KCHDR_SEGNAME "__KCHDR"

// Collect the input kernel's LC_SEGMENT_64 commands.
typedef struct {
  const struct segment_command_64 *lc;  // pointer into kernel_data
} SegRef;

int fileset_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size)
{
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
  const struct segment_command_64 *prelink_info = NULL;
  const struct segment_command_64 *prelink_text = NULL;
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
        if (!memcmp(sc->segname, "__PRELINK_TEXT", 14))
          prelink_text = sc;
      }
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
  // entry_id = bundle id, vmaddr = kext load address, fileoff = its offset within the KC file.
  //
  // These make the collection self-describing: kernel_collection_adjust_mh_addrs iterates them to fix each nested header,
  // and they mark every member as a real fileset component rather than opaque bytes in __PRELINK_TEXT.
  //
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

  // seg-only copies: segment_command_64 with nsects=0.  EXCEPT __PRELINK_INFO,
  // which must carry a __info section so XNU's getsectbynamefromheader() on the
  // KC header (readStartupExtensions) returns non-NULL.
  uint32_t seg_cmdsize = (uint32_t)sizeof(struct segment_command_64);
  uint32_t pi_cmdsize  = (uint32_t)(sizeof(struct segment_command_64) + sizeof(struct section_64));
  uint32_t chained_cmdsize = (uint32_t)sizeof(struct linkedit_data_command);

  uint32_t n_real_fe = 0; // non-codeless kext fileset entries actually emitted
  for (size_t i = 0; i < n_kext_fe; i++)
    if (kext_fe_cmdsize[i]) n_real_fe++;
  uint32_t kc_ncmds = 1 /*kernel entry*/ + n_real_fe + (uint32_t)nsegs + 1 /*chained*/;
  uint32_t kc_sizeofcmds = fe_cmdsize + kext_fe_total + chained_cmdsize;
  for (size_t i = 0; i < nsegs; i++)
    kc_sizeofcmds += (!memcmp(segs[i]->segname, "__PRELINK_INFO", 14)) ? pi_cmdsize : seg_cmdsize;
  uint32_t kc_hdr_bytes = (uint32_t)sizeof(struct mach_header_64) + kc_sizeofcmds;

  uint32_t fixups_off = (uint32_t)ALIGN_UP(kc_hdr_bytes, 8);
  uint32_t fixups_hdr = (uint32_t)sizeof(struct dyld_chained_fixups_header);
  uint32_t fixups_starts = 4; // just a uint32 seg_count == 0
  uint32_t fixups_size = fixups_hdr + fixups_starts;
  uint32_t kchdr_total = (uint32_t)ALIGN_UP(fixups_off + fixups_size, PAGE);

  uint8_t *kchdr = calloc(1, kchdr_total);
  if (!kchdr) return -1;

  // Place __KCHDR just above the kernel image (page aligned, low 32 bits form
  // the physical target our loader will use for KC_hdrs_vaddr).
  uint64_t kchdr_vmaddr = ALIGN_UP(kernel_vm_end, PAGE);

  {
    struct mach_header_64 *kh = (struct mach_header_64 *)kchdr;
    kh->magic = MH_MAGIC_64;
    kh->cputype = mh->cputype;
    kh->cpusubtype = mh->cpusubtype;
    kh->filetype = MH_FILESET;
    kh->ncmds = kc_ncmds;
    kh->sizeofcmds = kc_sizeofcmds;
    kh->flags = 0;

    uint8_t *p = kchdr + sizeof(*kh);

    // LC_FILESET_ENTRY for the kernel
    struct fileset_entry_command *fe = (struct fileset_entry_command *)p;
    fe->cmd = LC_FILESET_ENTRY;
    fe->cmdsize = fe_cmdsize;
    fe->vmaddr = first_seg_vmaddr;
    fe->fileoff = 0;
    fe->entry_id = (uint32_t)sizeof(struct fileset_entry_command);
    memcpy(p + fe->entry_id, kernel_entry_id, fe_idlen);
    p += fe_cmdsize;

    // LC_FILESET_ENTRY for each kext
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

    // Copies of the kernel's segments (seg-only, nsects=0), except
    // __PRELINK_INFO gets a __info section so getsectbynamefromheader() works.
    for (size_t i = 0; i < nsegs; i++) {
      struct segment_command_64 *dst = (struct segment_command_64 *)p;
      memcpy(dst, segs[i], sizeof(*dst));
      dst->cmd = LC_SEGMENT_64;
      if (!memcmp(segs[i]->segname, "__PRELINK_INFO", 14)) {
        dst->cmdsize = pi_cmdsize;
        dst->nsects = 1;
        struct section_64 *sec = (struct section_64 *)(dst + 1);
        memset(sec, 0, sizeof(*sec));
        memcpy(sec->sectname, "__info", 6);
        memcpy(sec->segname, "__PRELINK_INFO", 14);
        sec->addr = segs[i]->vmaddr;
        sec->size = segs[i]->filesize;
        sec->offset = (uint32_t)segs[i]->fileoff;
        p += pi_cmdsize;
      } else {
        dst->cmdsize = seg_cmdsize;
        dst->nsects = 0;
        p += seg_cmdsize;
      }
    }

    // LC_DYLD_CHAINED_FIXUPS -> empty blob (offsets are relative to __KCHDR
    // start; the loader maps __KCHDR so dataoff must be within it).
    struct linkedit_data_command *cf = (struct linkedit_data_command *)p;
    cf->cmd = LC_DYLD_CHAINED_FIXUPS;
    cf->cmdsize = chained_cmdsize;
    cf->dataoff = fixups_off; // NOTE: relative to KC header start
    cf->datasize = fixups_size;
    p += chained_cmdsize;

    // Empty fixups payload
    struct dyld_chained_fixups_header *fh = (struct dyld_chained_fixups_header *)(kchdr + fixups_off);
    fh->fixups_version = 0;
    fh->starts_offset = fixups_hdr;
    fh->imports_offset = fixups_hdr + fixups_starts;
    fh->symbols_offset = fixups_hdr + fixups_starts;
    fh->imports_count = 0;
    fh->imports_format = 1;
    fh->symbols_format = 0;
    // starts_in_image.seg_count = 0
    *(uint32_t *)(kchdr + fixups_off + fixups_hdr) = 0;
  }

  uint32_t new_seg_cmdsize = (uint32_t)sizeof(struct segment_command_64);
  size_t hdr_cmds_end = sizeof(*mh) + mh->sizeofcmds;
  // First byte of real segment data (limits header growth)
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
  if (hdr_cmds_end + new_seg_cmdsize > body_off) {
    fprintf(stderr, "fileset: no header room for __KCHDR LC\n");
    free(kchdr);
    return -1;
  }

  size_t kchdr_fileoff = ALIGN_UP(base_size, PAGE);
  size_t total = kchdr_fileoff + kchdr_total;
  uint8_t *out = calloc(1, total);
  if (!out) { free(kchdr); return -1; }
  memcpy(out, base_data, base_size);
  memcpy(out + kchdr_fileoff, kchdr, kchdr_total);
  free(kchdr);

  struct mach_header_64 *omh = (struct mach_header_64 *)out;

  // Set MH_DYLIB_IN_CACHE so XNU treats the kernel as part of a fileset.
  omh->flags |= MH_DYLIB_IN_CACHE;

  // Append the __KCHDR segment command.
  {
    struct segment_command_64 *sc =
        (struct segment_command_64 *)(out + sizeof(*omh) + omh->sizeofcmds);
    memset(sc, 0, sizeof(*sc));
    sc->cmd = LC_SEGMENT_64;
    sc->cmdsize = new_seg_cmdsize;
    memcpy(sc->segname, KCHDR_SEGNAME, sizeof(KCHDR_SEGNAME) - 1);
    sc->vmaddr = kchdr_vmaddr;
    sc->vmsize = kchdr_total;
    sc->fileoff = kchdr_fileoff;
    sc->filesize = kchdr_total;
    sc->maxprot = VM_PROT_READ;
    sc->initprot = VM_PROT_READ;
    sc->nsects = 0;
    omh->ncmds++;
    omh->sizeofcmds += new_seg_cmdsize;
  }

  // maybe I should include stdint lmao
  fprintf(stderr, "fileset: __KCHDR vmaddr=0x%llx fileoff=0x%zx size=0x%x -> KC_hdrs phys=0x%llx\n",
          (unsigned long long)kchdr_vmaddr, kchdr_fileoff, kchdr_total, (unsigned long long)(kchdr_vmaddr & 0x3FFFFFFF));

  *out_data = out;
  *out_size = total;
  return 0;
}
