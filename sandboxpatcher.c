/*
 * sb_patch.c — Sandbox.kext mac_policy_ops nop-stub patcher
 * Target: tvOS 16.0 beta 2 A8 kernelcache (kernel.raw, decrypted merged Mach-O)
 * Purpose: patch every mac_policy_ops hook to "mov w0, #0 ; ret" so Sandbox
 *          returns 0 (allow) for all MACF checks.
 *
 * WARNING: this disables the sandbox entirely. It's a blunt instrument to get
 * past the SANDBOX/SIGKILL on mtmergeprops when running iPadOS 16 userland on
 * iPad mini 4 (iPad5,1). Tighten up or profile-patch later.
 *
 * Addresses are hardcoded from lief analysis of this specific kernelcache.
 * If you use a different build, re-derive them (see comments below).
 *
 * Build:  cc -O2 -o sb_patch sb_patch.c
 * Usage:  ./sb_patch kernel.raw            # patch in place (make a backup first!)
 *         ./sb_patch kernel.raw --dry-run  # just print what would be patched
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
/* mov w0, #0  →  52 80 00 00  (little-endian: 00 00 80 52)                   */
/* ret         →  c0 03 5f d6                                                  */
static const uint32_t STUB[2] = { 0x52800000u, 0xD65F03C0u };

/* ── Mach-O types / constants ─────────────────────────────────────────────── */
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

/* ── Segment table ────────────────────────────────────────────────────────── */
#define MAX_SEGS 32
typedef struct { char name[17]; uint64_t va, size, foff; } seg_t;
static seg_t segs[MAX_SEGS];
static int   nseg = 0;

static uint64_t va_to_foff(uint64_t va) {
    for (int i = 0; i < nseg; i++)
        if (va >= segs[i].va && va < segs[i].va + segs[i].size)
            return segs[i].foff + (va - segs[i].va);
    return UINT64_MAX;
}

/* ── Hardcoded Sandbox.kext layout (tvOS 16.0b2 A8, 20J5319d) ─────────────
 *
 *  Derived from:
 *    __PRELINK_INFO → com.apple.security.sandbox entry:
 *      _PrelinkExecutableLoadAddr = 0xfffffff005a53d80   (__PRELINK_TEXT, kext Mach-O header)
 *      _PrelinkExecutableSize     = 0x000eb157
 *    lief segment parse of extracted kext Mach-O:
 *      __TEXT_EXEC  va=0xfffffff0065af000  size=0x286f8   (in __PLK_TEXT_EXEC)
 *      __DATA_CONST va=0xfffffff006ea7bc0  size=0x3788    (in __PLK_DATA_CONST)
 *
 *  To re-derive for a different kernelcache:
 *    1) strings -a -t x kernel.raw | grep com.apple.security.sandbox
 *       → find the __PRELINK_INFO entry, extract _PrelinkExecutableLoadAddr
 *    2) parse that address as a Mach-O header (it's inside __PRELINK_TEXT)
 *       → get __TEXT_EXEC and __DATA_CONST segment VAs & sizes from LC_SEGMENT_64
 * ────────────────────────────────────────────────────────────────────────── */
#define SB_TEXT_VA    0xfffffff0065af000ULL
#define SB_TEXT_SIZE  0x286f8ULL
#define SB_DATA_VA    0xfffffff006ea7bc0ULL
#define SB_DATA_SIZE  0x3788ULL

/* ────────────────────────────────────────────────────────────────────────── */

static void parse_segments(const uint8_t *buf) {
    const mh64_t *mh = (const mh64_t *)buf;
    const uint8_t *lcp = buf + sizeof(mh64_t);
    for (uint32_t i = 0; i < mh->ncmds && nseg < MAX_SEGS; i++) {
        const lc_t  *l = (const lc_t *)lcp;
        if (l->cmd == LC_SEGMENT_64) {
            const seg64_t *s = (const seg64_t *)lcp;
            seg_t *g = &segs[nseg++];
            memcpy(g->name, s->segname, 16); g->name[16] = '\0';
            g->va = s->vmaddr; g->size = s->vmsize; g->foff = s->fileoff;
        }
        lcp += l->cmdsize;
    }
}

int main(int argc, char **argv) {
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

    /* Validate Mach-O magic */
    if (fsz < sizeof(mh64_t) || ((mh64_t*)buf)->magic != MH_MAGIC_64) {
        fprintf(stderr, "[-] Not a 64-bit Mach-O (bad magic)\n"); return 1;
    }

    parse_segments(buf);
    printf("[*] Parsed %d segments\n", nseg);

    /* Resolve Sandbox regions */
    uint64_t sb_text_foff = va_to_foff(SB_TEXT_VA);
    uint64_t sb_data_foff = va_to_foff(SB_DATA_VA);

    if (sb_text_foff == UINT64_MAX) {
        fprintf(stderr,
            "[-] Couldn't resolve Sandbox TEXT_EXEC VA 0x%llx\n"
            "    Wrong kernelcache? Re-derive SB_TEXT_VA from PRELINK_INFO.\n",
            (unsigned long long)SB_TEXT_VA);
        return 1;
    }
    if (sb_data_foff == UINT64_MAX) {
        fprintf(stderr,
            "[-] Couldn't resolve Sandbox DATA_CONST VA 0x%llx\n",
            (unsigned long long)SB_DATA_VA);
        return 1;
    }

    printf("[*] Sandbox.kext TEXT_EXEC  VA=0x%llx  foff=0x%llx  size=0x%llx\n",
           (unsigned long long)SB_TEXT_VA,
           (unsigned long long)sb_text_foff,
           (unsigned long long)SB_TEXT_SIZE);
    printf("[*] Sandbox.kext DATA_CONST VA=0x%llx  foff=0x%llx  size=0x%llx\n",
           (unsigned long long)SB_DATA_VA,
           (unsigned long long)sb_data_foff,
           (unsigned long long)SB_DATA_SIZE);

    if (sb_data_foff + SB_DATA_SIZE > fsz || sb_text_foff + SB_TEXT_SIZE > fsz) {
        fprintf(stderr, "[-] Region extends beyond file — corrupted input?\n");
        return 1;
    }

    /*
     * Scan DATA_CONST for 8-byte aligned pointers into Sandbox TEXT_EXEC.
     * These are the non-null entries in the mac_policy_ops struct.
     * Null slots (unimplemented hooks) are skipped — no function to patch there.
     *
     * Note: this kernel is arm64 (A8, not arm64e), so no PAC bits to strip.
     * Pointers are stored as raw VAs (pre-KASLR slide = 0 base).
     */
    const uint64_t *data_const = (const uint64_t *)(buf + sb_data_foff);
    size_t nslots = SB_DATA_SIZE / 8;

    int patched  = 0;
    int skipped  = 0;   /* already stubbed */
    int too_small = 0;  /* function body < 8 bytes from region end — shouldn't happen */

    printf("[*] Scanning %zu pointer slots in DATA_CONST...\n\n", nslots);

    for (size_t i = 0; i < nslots; i++) {
        uint64_t ptr = data_const[i];

        /* Must point into Sandbox TEXT_EXEC */
        if (ptr < SB_TEXT_VA || ptr >= SB_TEXT_VA + SB_TEXT_SIZE)
            continue;

        uint64_t fn_foff = va_to_foff(ptr);
        if (fn_foff == UINT64_MAX) continue;

        /* Sanity: need at least 8 bytes */
        if (fn_foff + 8 > fsz) { too_small++; continue; }

        uint32_t *insn = (uint32_t *)(buf + fn_foff);

        /* Already stubbed? */
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
        printf("[!] Skipped (too small):  %d  (bug — investigate)\n", too_small);

    if (dry)
        printf("[*] Dry run — no changes written.\n");
    else
        printf("[*] Done. Flush: msync'd via MAP_SHARED.\n");

    if (!dry && msync(buf, fsz, MS_SYNC) != 0)
        perror("[!] msync");

    munmap(buf, fsz);
    return 0;
}
