/*
 * sb_patch.c — Sandbox.kext mac_policy_ops nop-stub patcher
 *
 * Patches every mac_policy_ops hook in Sandbox.kext to
 * "mov w0, #0 ; ret" so the sandbox returns 0 (allow) for all MACF checks.
 *
 * Works on any arm64 (non-PAC) prelinked kernelcache whose __PRELINK_INFO
 * contains a com.apple.security.sandbox entry with a parseable Mach-O header
 * at its _PrelinkExecutableLoadAddr.
 *
 * Bug fixed vs previous version:
 *   find_sandbox_regions() now searches a tight 2 KB window BACKWARD from
 *   the CFBundleIdentifier match and takes the LAST (closest) occurrence of
 *   _PrelinkExecutableLoadAddr, instead of the first occurrence in a 16 KB
 *   window that spans many earlier kext entries and thus matches the wrong kext.
 *
 *   On tvOS 16.1 the plist has many kext entries between the prior kext that
 *   happened to be matched and the real Sandbox entry, causing the old code to
 *   patch a completely different kext (IOCECUserClient) while leaving the real
 *   Sandbox.kext untouched.
 *
 * Build:  cc -O2 -o sb_patch sb_patch.c
 * Usage:  ./sb_patch kernel.raw [--dry-run]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* ── AArch64 stub ─────────────────────────────────────────────────────────── */
static const uint32_t STUB[2] = { 0x52800000u, 0xD65F03C0u };

/* ── Mach-O types ─────────────────────────────────────────────────────────── */
#define MH_MAGIC_64    0xFEEDFACFu
#define LC_SEGMENT_64  0x00000019u

typedef struct {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
} mh64_t;

typedef struct { uint32_t cmd, cmdsize; } lc_t;

typedef struct {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
} seg64_t;

/* ── Kernel segment table ─────────────────────────────────────────────────── */
#define MAX_SEGS 32
typedef struct { char name[17]; uint64_t va, size, foff; } seg_t;
static seg_t segs[MAX_SEGS];
static int   nseg = 0;

static void parse_kernel_segments(const uint8_t *buf)
{
    const mh64_t *mh = (const mh64_t *)buf;
    const uint8_t *lcp = buf + sizeof(mh64_t);
    for (uint32_t i = 0; i < mh->ncmds && nseg < MAX_SEGS; i++) {
        const lc_t *l = (const lc_t *)lcp;
        if (l->cmd == LC_SEGMENT_64) {
            const seg64_t *s = (const seg64_t *)lcp;
            seg_t *g = &segs[nseg++];
            memcpy(g->name, s->segname, 16); g->name[16] = '\0';
            g->va   = s->vmaddr;
            g->size = s->vmsize;
            g->foff = s->fileoff;
        }
        lcp += l->cmdsize;
    }
}

static uint64_t va_to_foff(uint64_t va)
{
    for (int i = 0; i < nseg; i++)
        if (va >= segs[i].va && va < segs[i].va + segs[i].size)
            return segs[i].foff + (va - segs[i].va);
    return UINT64_MAX;
}

/* ── PRELINK_INFO helpers ─────────────────────────────────────────────────── */

static int find_prelink_info(const uint8_t *buf, size_t bufsz,
                             uint64_t *foff, uint64_t *fsz)
{
    const mh64_t *mh = (const mh64_t *)buf;
    const uint8_t *lcp = buf + sizeof(mh64_t);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const lc_t *l = (const lc_t *)lcp;
        if (l->cmd == LC_SEGMENT_64) {
            const seg64_t *s = (const seg64_t *)lcp;
            if (!strncmp(s->segname, "__PRELINK_INFO", 16)) {
                *foff = s->fileoff;
                *fsz  = s->filesize;
                return (s->fileoff + s->filesize <= bufsz);
            }
        }
        lcp += l->cmdsize;
        if (lcp + 8 > buf + bufsz) break;
    }
    return 0;
}

static const char *mem_find(const char *hay, size_t hlen,
                            const char *needle, size_t nlen)
{
    if (!nlen || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen))
            return hay + i;
    return NULL;
}

/*
 * Find the LAST occurrence of needle in [hay, hay+hlen).
 * Returns a pointer to it, or NULL.
 */
static const char *mem_rfind(const char *hay, size_t hlen,
                             const char *needle, size_t nlen)
{
    if (!nlen || hlen < nlen) return NULL;
    const char *last = NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen))
            last = hay + i;
    return last;
}

/*
 * Parse a uint64_t hex/dec value from a plist <integer> tag whose opening
 * '>' has already been consumed; *p points just past it.  Returns 1 on success.
 */
static int parse_plist_int(const char *p, const char *end, uint64_t *val)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
    if (p >= end) return 0;
    char *endp;
    *val = strtoull(p, &endp, 0);
    return endp != p;
}

/*
 * Locate the Sandbox.kext prelink entry and extract its __TEXT_EXEC and
 * __DATA_CONST virtual address and size from the embedded kext Mach-O.
 *
 * KEY FIX: The previous version searched a 16 KB window centred BEFORE the
 * CFBundleIdentifier string match for _PrelinkExecutableLoadAddr.  With many
 * kext entries in that window, it matched the WRONG entry's LoadAddr.
 *
 * The corrected logic:
 *   1. Locate CFBundleIdentifier = com.apple.security.sandbox.
 *   2. In a 2 KB window BEFORE that hit, find the LAST (i.e. closest/most
 *      recent) _PrelinkExecutableLoadAddr.  The LoadAddr key always appears
 *      earlier in the same <dict> entry than CFBundleIdentifier, so 2 KB
 *      backward is more than enough and small enough not to reach a prior
 *      entry's LoadAddr.
 *   3. Parse the kext Mach-O at that address.
 *
 * Returns 1 on success, 0 on failure.
 */
static int find_sandbox_regions(const uint8_t *buf, size_t bufsz,
                                uint64_t *text_va,  uint64_t *text_sz,
                                uint64_t *data_va,  uint64_t *data_sz)
{
    uint64_t info_foff, info_fsz;
    if (!find_prelink_info(buf, bufsz, &info_foff, &info_fsz)) {
        fprintf(stderr, "[-] __PRELINK_INFO not found\n");
        return 0;
    }

    const char *info = (const char *)buf + info_foff;
    size_t info_len  = info_fsz;
    while (info_len && info[info_len - 1] == '\0') info_len--;

    /* Step 1: find the Sandbox CFBundleIdentifier. */
    static const char SB_ID[] =
        "<key>CFBundleIdentifier</key>"
        "<string>com.apple.security.sandbox</string>";
    const size_t SB_ID_LEN = sizeof(SB_ID) - 1;

    const char *id_hit = mem_find(info, info_len, SB_ID, SB_ID_LEN);
    if (!id_hit) {
        fprintf(stderr, "[-] Sandbox.kext entry not found in __PRELINK_INFO\n");
        return 0;
    }
    printf("[*] Sandbox CFBundleIdentifier at info+0x%zx\n",
           (size_t)(id_hit - info));

    /*
     * Step 2: find the LAST _PrelinkExecutableLoadAddr in the 2 KB before
     * the CFBundleIdentifier hit.  "Last" = closest to the hit = the one
     * belonging to the same <dict> entry.
     *
     * We use 2048 bytes: the LoadAddr key is always within a few hundred
     * bytes before the CFBundleIdentifier in any Apple prelink plist, while
     * the prior kext entry ends well before that.
     */
    static const char LA_KEY[] = "<key>_PrelinkExecutableLoadAddr</key>";
    const size_t LA_KEY_LEN = sizeof(LA_KEY) - 1;

    size_t id_off = (size_t)(id_hit - info);
    size_t win_start = (id_off > 2048) ? id_off - 2048 : 0;
    size_t win_len   = id_off - win_start;

    const char *la_key = mem_rfind(info + win_start, win_len, LA_KEY, LA_KEY_LEN);
    if (!la_key) {
        fprintf(stderr,
            "[-] _PrelinkExecutableLoadAddr not found in 2 KB before "
            "CFBundleIdentifier\n"
            "    info window: +0x%zx .. +0x%zx\n",
            win_start, id_off);
        return 0;
    }

    /* Skip past the key to the <integer ...> tag. */
    const char *p = la_key + LA_KEY_LEN;
    const char *info_end = info + info_len;

    /* skip to '>' of <integer ...> */
    const char *gt = memchr(p, '>', (size_t)(info_end - p));
    if (!gt) { fprintf(stderr, "[-] Bad plist integer tag for LoadAddr\n"); return 0; }
    p = gt + 1;

    uint64_t load_addr;
    if (!parse_plist_int(p, info_end, &load_addr)) {
        fprintf(stderr, "[-] Failed to parse Sandbox LoadAddr value\n");
        return 0;
    }

    printf("[*] Sandbox.kext _PrelinkExecutableLoadAddr = 0x%llx\n",
           (unsigned long long)load_addr);

    /* Step 3: map to file offset and parse kext Mach-O. */
    uint64_t kext_foff = va_to_foff(load_addr);
    if (kext_foff == UINT64_MAX) {
        fprintf(stderr, "[-] Cannot map Sandbox load addr 0x%llx to file offset\n",
                (unsigned long long)load_addr);
        return 0;
    }
    printf("[*] Sandbox.kext Mach-O at file offset 0x%llx\n",
           (unsigned long long)kext_foff);

    if (kext_foff + 64 > bufsz) {
        fprintf(stderr, "[-] Sandbox kext Mach-O header out of file\n");
        return 0;
    }

    const uint8_t *kext = buf + kext_foff;
    const mh64_t  *kmh  = (const mh64_t *)kext;
    if (kmh->magic != MH_MAGIC_64) {
        fprintf(stderr, "[-] Sandbox kext bad Mach-O magic: 0x%x\n", kmh->magic);
        return 0;
    }

    *text_va = 0; *text_sz = 0;
    *data_va = 0; *data_sz = 0;

    const uint8_t *lcp = kext + sizeof(mh64_t);
    for (uint32_t i = 0; i < kmh->ncmds; i++) {
        if (lcp + sizeof(lc_t) > kext + 0x80000) break;
        const lc_t *l = (const lc_t *)lcp;
        if (l->cmd == LC_SEGMENT_64 && l->cmdsize >= sizeof(seg64_t)) {
            const seg64_t *s = (const seg64_t *)lcp;
            if (!strncmp(s->segname, "__TEXT_EXEC",  16)) {
                *text_va = s->vmaddr; *text_sz = s->vmsize;
            } else if (!strncmp(s->segname, "__DATA_CONST", 16)) {
                *data_va = s->vmaddr; *data_sz = s->vmsize;
            }
        }
        lcp += l->cmdsize;
    }

    if (!*text_va || !*data_va) {
        fprintf(stderr,
            "[-] Sandbox kext missing __TEXT_EXEC or __DATA_CONST\n"
            "    text_va=0x%llx data_va=0x%llx\n"
            "    Is this the right kernel? "
            "Verify CFBundleName is 'Seatbelt sandbox policy'.\n",
            (unsigned long long)*text_va, (unsigned long long)*data_va);
        return 0;
    }

    return 1;
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <kernel.raw> [--dry-run]\n"
            "       --dry-run  scan and report, do not write\n", argv[0]);
        return 1;
    }
    int dry = (argc >= 3 && strcmp(argv[2], "--dry-run") == 0);

    int fd = open(argv[1], dry ? O_RDONLY : O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); return 1; }
    size_t fsz = (size_t)st.st_size;

    int prot  = PROT_READ | (dry ? 0 : PROT_WRITE);
    int flags = dry ? MAP_PRIVATE : MAP_SHARED;
    uint8_t *buf = mmap(NULL, fsz, prot, flags, fd, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    close(fd);

    if (fsz < sizeof(mh64_t) || ((mh64_t *)buf)->magic != MH_MAGIC_64) {
        fprintf(stderr, "[-] Not a 64-bit Mach-O (bad magic)\n");
        return 1;
    }

    parse_kernel_segments(buf);
    printf("[*] Parsed %d kernel segments\n", nseg);

    uint64_t sb_text_va, sb_text_sz, sb_data_va, sb_data_sz;
    if (!find_sandbox_regions(buf, fsz,
                              &sb_text_va, &sb_text_sz,
                              &sb_data_va, &sb_data_sz))
        return 1;

    uint64_t sb_text_foff = va_to_foff(sb_text_va);
    uint64_t sb_data_foff = va_to_foff(sb_data_va);

    if (sb_text_foff == UINT64_MAX || sb_data_foff == UINT64_MAX) {
        fprintf(stderr,
            "[-] Cannot map Sandbox segment VAs to file offsets\n"
            "    TEXT_EXEC VA=0x%llx  DATA_CONST VA=0x%llx\n",
            (unsigned long long)sb_text_va, (unsigned long long)sb_data_va);
        return 1;
    }

    printf("[*] Sandbox.kext TEXT_EXEC  VA=0x%llx  foff=0x%llx  size=0x%llx\n",
           (unsigned long long)sb_text_va,
           (unsigned long long)sb_text_foff,
           (unsigned long long)sb_text_sz);
    printf("[*] Sandbox.kext DATA_CONST VA=0x%llx  foff=0x%llx  size=0x%llx\n",
           (unsigned long long)sb_data_va,
           (unsigned long long)sb_data_foff,
           (unsigned long long)sb_data_sz);

    if (sb_data_foff + sb_data_sz > fsz || sb_text_foff + sb_text_sz > fsz) {
        fprintf(stderr, "[-] Region extends beyond file — corrupted input?\n");
        return 1;
    }

    /*
     * Scan DATA_CONST for 8-byte aligned pointers into Sandbox TEXT_EXEC.
     * Non-null entries pointing into TEXT_EXEC are mac_policy_ops hook pointers.
     * Null slots (unimplemented hooks) are skipped.
     *
     * Note: arm64 (A8), not arm64e — no PAC bits, pointers are raw VAs.
     */
    const uint64_t *data_const = (const uint64_t *)(buf + sb_data_foff);
    size_t nslots = (size_t)(sb_data_sz / 8);

    int patched   = 0;
    int skipped   = 0;
    int too_small = 0;

    printf("[*] Scanning %zu pointer slots in DATA_CONST...\n\n", nslots);

    for (size_t i = 0; i < nslots; i++) {
        uint64_t ptr = data_const[i];

        if (ptr < sb_text_va || ptr >= sb_text_va + sb_text_sz)
            continue;

        uint64_t fn_foff = va_to_foff(ptr);
        if (fn_foff == UINT64_MAX) continue;

        if (fn_foff + 8 > fsz) { too_small++; continue; }

        uint32_t *insn = (uint32_t *)(buf + fn_foff);

        if (insn[0] == STUB[0] && insn[1] == STUB[1]) { skipped++; continue; }

        printf("%s hook @ DATA_CONST+0x%04zx  fn_VA=0x%llx  fn_foff=0x%llx\n",
               dry ? "    [DRY]" : "[PATCH]",
               i * 8,
               (unsigned long long)ptr,
               (unsigned long long)fn_foff);

        if (!dry) {
            insn[0] = STUB[0];
            insn[1] = STUB[1];
        }
        patched++;
    }

    printf("\n");
    printf("[*] %-12s  %d mac_policy_ops hooks\n",
           dry ? "Would patch" : "Patched", patched);
    printf("[*] Already stubbed: %d\n", skipped);
    if (too_small)
        printf("[!] Skipped (too small): %d  (investigate)\n", too_small);

    if (dry)
        printf("[*] Dry run — no changes written.\n");
    else {
        printf("[*] Done.\n");
        if (msync(buf, fsz, MS_SYNC) != 0) perror("[!] msync");
    }

    munmap(buf, fsz);
    return 0;
}
