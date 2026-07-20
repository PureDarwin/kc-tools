#include "prelink.h"
#include "plist.h"
#include "macho_fmt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PAGE 0x1000ULL
#define ALIGN_UP(x, a) (((uint64_t)(x) + ((uint64_t)(a) - 1)) & ~((uint64_t)(a) - 1))

// Collect the input kernel's LC_SEGMENT_64 commands.
typedef struct {
  const struct segment_command_64 *lc;  // pointer into kernel_data
} SegRef;

int fileset_assemble(const uint8_t *kernel_data, size_t kernel_size,
                     LinkedKext *kexts, size_t num_kexts,
                     uint8_t **out_data, size_t *out_size)
{
  uint8_t *base_data = (uint8_t *)kernel_data;
  size_t base_size = kernel_size;
  int base_owned = 0;
  size_t *header_foffs = num_kexts ? calloc(num_kexts, sizeof(size_t)) : NULL;
  if (num_kexts > 0) {
    if (prelink_assemble_kc(kernel_data, kernel_size, kexts, num_kexts,
                            &base_data, &base_size, header_foffs) != 0) {
      fprintf(stderr, "fileset: prelink_assemble_kc failed\n");
      free(header_foffs);
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

  if (base_owned && header_foffs) {
    for (size_t i = 0; i < num_kexts; i++) {
      if (kexts[i].codeless) continue;
      size_t koff = header_foffs[i];
      if (koff == 0 || koff + sizeof(struct mach_header_64) > base_size) continue;
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
  (void)prelink_info; (void)prelink_text; (void)kexts; (void)num_kexts;

  fprintf(stderr, "fileset: kernel hdr vmaddr=0x%llx vm_end=0x%llx segs=%zu\n",
          (unsigned long long)first_seg_vmaddr,
          (unsigned long long)kernel_vm_end, nsegs);

  static const char kernel_entry_id[] = "com.apple.kernel";
  uint32_t fe_idlen = (uint32_t)sizeof(kernel_entry_id); // incl NUL
  uint32_t fe_cmdsize = (uint32_t)ALIGN_UP(sizeof(struct fileset_entry_command) + fe_idlen, 8);

  uint32_t kext_fe_cmdsize[64];
  uint32_t kext_fe_total = 0;
  size_t n_kext_fe = num_kexts;
  if (n_kext_fe > 64) n_kext_fe = 64;
  for (size_t i = 0; i < n_kext_fe; i++) {
    if (kexts[i].codeless) { kext_fe_cmdsize[i] = 0; continue; }  // no segments
    uint32_t idlen = (uint32_t)strlen(kexts[i].bundle_id) + 1;
    uint32_t cs = (uint32_t)ALIGN_UP(sizeof(struct fileset_entry_command) + idlen, 8);
    kext_fe_cmdsize[i] = cs;
    kext_fe_total += cs;
  }

  uint32_t chained_cmdsize = (uint32_t)sizeof(struct linkedit_data_command);

  uint32_t n_real_fe = 0; // non-codeless kext fileset entries actually emitted
  for (size_t i = 0; i < n_kext_fe; i++)
    if (kext_fe_cmdsize[i]) n_real_fe++;

  uint32_t new_ncmds = 1 + n_real_fe + 1;
  uint32_t new_cmds_size = fe_cmdsize + kext_fe_total + chained_cmdsize;

  uint32_t fixups_hdr_size = (uint32_t)sizeof(struct dyld_chained_fixups_header);
  uint32_t fixups_starts_size = 4; // just a uint32 seg_count == 0
  uint32_t fixups_size = fixups_hdr_size + fixups_starts_size;

  size_t hdr_cmds_end = sizeof(*mh) + mh->sizeofcmds;
  size_t new_cmds_off = hdr_cmds_end;                                // where the new LCs start

  size_t linkedit_off = 0, linkedit_fileoff = 0, linkedit_filesize = 0;
  uint64_t linkedit_vmsize = 0;
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
  size_t fixups_off = ALIGN_UP(linkedit_fileoff + linkedit_filesize, 8);
  if (fixups_off + fixups_size > next_seg_fileoff) {
    fprintf(stderr,
            "fileset: no room after __LINKEDIT to place chained fixups "
            "(need up to 0x%zx, next segment's file data starts at 0x%llx)\n",
            fixups_off + fixups_size, (unsigned long long)next_seg_fileoff);
    if (base_owned) free(base_data);
    return -1;
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

  uint8_t *out = calloc(1, base_size);
  if (!out) { if (base_owned) free(base_data); return -1; }
  memcpy(out, base_data, base_size);
  if (base_owned) free(base_data);

  struct mach_header_64 *omh = (struct mach_header_64 *)out;
  omh->filetype = MH_FILESET;
  omh->flags |= MH_DYLIB_IN_CACHE; // kernel_mach_header_is_in_fileset() only checks this flag
  omh->ncmds += new_ncmds;
  omh->sizeofcmds += new_cmds_size;

  // Extend __LINKEDIT's own filesize/vmsize to genuinely cover the fixups
  // blob we're about to write into its trailing alignment padding.
  {
    struct segment_command_64 *le = (struct segment_command_64 *)(out + linkedit_off);
    uint64_t new_filesize = (fixups_off + fixups_size) - linkedit_fileoff;
    uint64_t grew = new_filesize - linkedit_filesize;
    le->filesize = new_filesize;
    le->vmsize = linkedit_vmsize + grew;
  }

  // Kernel-only KC (no kexts): prelink_assemble_kc never ran, so still do
  // the baseline __DATA_CONST/__DATA growth to satisfy arm_vm_init's
  // containment asserts against __LASTDATA_CONST/__PRELINK_DATA.
  if (!base_owned) {
    struct segment_command_64 *dc = NULL, *ldc = NULL, *data = NULL;
    uint64_t pd_vmaddr = 0;
    uint8_t *lcp2 = out + sizeof(*omh);
    for (uint32_t i = 0; i < omh->ncmds; i++) {
      struct load_command *lc = (struct load_command *)lcp2;
      if (lc->cmd == LC_SEGMENT_64) {
        struct segment_command_64 *sc = (struct segment_command_64 *)lcp2;
        if (!memcmp(sc->segname, "__DATA_CONST", 13)) dc = sc;
        else if (!memcmp(sc->segname, "__LASTDATA_CONST", 17)) ldc = sc;
        else if (!memcmp(sc->segname, "__DATA", 7)) data = sc;
        else if (!memcmp(sc->segname, "__PRELINK_DATA", 15)) pd_vmaddr = sc->vmaddr;
      }
      lcp2 += lc->cmdsize;
    }
    if (dc && ldc && ldc->vmaddr + ldc->vmsize > dc->vmaddr + dc->vmsize)
      dc->vmsize = (ldc->vmaddr + ldc->vmsize) - dc->vmaddr;
    if (data && pd_vmaddr && data->vmaddr + data->vmsize < pd_vmaddr)
      data->vmsize = pd_vmaddr - data->vmaddr;
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
    ke->vmaddr = kexts[i].header_vmaddr;
    ke->fileoff = header_foffs ? header_foffs[i] : 0;
    ke->entry_id = (uint32_t)sizeof(struct fileset_entry_command);
    ke->reserved = 0;
    memcpy(p + ke->entry_id, kexts[i].bundle_id, idlen);
    p += kext_fe_cmdsize[i];
  }

  struct linkedit_data_command *cf = (struct linkedit_data_command *)p;
  cf->cmd = LC_DYLD_CHAINED_FIXUPS;
  cf->cmdsize = chained_cmdsize;
  cf->dataoff = (uint32_t)fixups_off;
  cf->datasize = fixups_size;

  struct dyld_chained_fixups_header *fh =
      (struct dyld_chained_fixups_header *)(out + fixups_off);
  fh->fixups_version = 0;
  fh->starts_offset = fixups_hdr_size;
  fh->imports_offset = fixups_hdr_size + fixups_starts_size;
  fh->symbols_offset = fixups_hdr_size + fixups_starts_size;
  fh->imports_count = 0;
  fh->imports_format = 1;
  fh->symbols_format = 0;
  // starts_in_image.seg_count = 0
  *(uint32_t *)(out + fixups_off + fixups_hdr_size) = 0;

  fprintf(stderr,
          "fileset: converted kernel header in place: vmaddr=0x%llx "
          "ncmds=%u sizeofcmds=%u (grew by %u bytes), fixups at fileoff=0x%zx\n",
          (unsigned long long)first_seg_vmaddr, omh->ncmds, omh->sizeofcmds,
          new_cmds_size, fixups_off);

  *out_data = out;
  *out_size = base_size;
  free(header_foffs);
  return 0;
}
