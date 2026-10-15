/*
 * pmupatch_d2207.c
 *
 * Targeted "PMU for touch" patch for an Apple TV (tvOS 16.x, A8/t7000)
 * prelinked kernelcache used to boot an iPad mini 4 (J96).
 *
 * This is a drop-in replacement for the original pmupatch_d2207.c with all
 * hardcoded absolute VAs and fixed file-offset assumptions removed.
 *
 * What changed from the original
 * --------------------------------
 *  - OFF_BOOST_CAVE / OFF_GPIO_CAVE were fixed offsets from the mask anchor
 *    that assumed a particular TEXT_EXEC size.  They now come from the kext's
 *    actual TEXT_EXEC end, derived by parsing the embedded D2186PMU Mach-O
 *    header found at _PrelinkExecutableLoadAddr.  The caves are placed at the
 *    first aligned zero-filled word after the kext's last instruction.
 *  - OFF_BOOST_PATCH (anchor + 0x240) is unchanged: it is the distance from
 *    the mask anchor to the strb patch point, which is a structural property
 *    of the _setLDO function and is verified by SIG_BOOST_CTX before use.
 *  - BOOST_CAVE[7] (the back-branch from cave to patch_point+4) is now
 *    computed at runtime via arm64_b() so it stays correct regardless of where
 *    the cave lands relative to patch_point.
 *  - The plist-side (IONameMatch pmu,d2186→pmu,d2207) and all byte/word
 *    signatures are unchanged; they matched both 16.0b2 and 16.1.
 *
 * Usage:
 *   cc -O2 -Wall -Wextra -o pmupatch_d2207 pmupatch_d2207.c
 *   ./pmupatch_d2207 [-n] [-k] [-K] [-B] [-v] in.raw [out.raw]
 *
 *   -n  dry run
 *   -k  keep RTC/watchdog personalities (default)
 *   -K  disable RTC/watchdog personalities
 *   -B  skip 5V boost trampoline
 *   -v  verbose
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MH_MAGIC_64   0xfeedfacfu
#define LC_SEGMENT_64 0x19u

/* ------------------------------------------------------------------ */
/* D2186 LDO table (20 rows × 12 bytes = 240 bytes).                  */
/* ------------------------------------------------------------------ */
static const uint8_t D2186_LDO_TABLE[240] = {
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x0c,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x92,0x00,0x40,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x40,0x00,
};

static const uint8_t D2207_LDO_TABLE[240] = {
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x19,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x70,0x03,0x83,0x00,0x40,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x04,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x08,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
};

#define LDO_ROWS  20
#define LDO_BYTES (LDO_ROWS * 12)

/* ── Instruction signatures ─────────────────────────────────────────────── */

/* _setLDO mask sequence (6 words). */
static const uint32_t SIG_MASKS[6] = {
    0x529d0008u, 0x72a001e8u, 0x9ad92508u,
    0x37000088u, 0x5282ffe8u, 0x9ad92508u
};
#define NEW_MASK_A_LO  0x52810008u
#define NEW_MASK_A_HI  0x72a00fc8u
#define NEW_MASK_B     0x320043e8u
#define OLD_MOV_W1_380 0x52807001u
#define NEW_MOV_W1_391 0x52807221u

/* D2186 GPIO→register mapper (6 words). */
static const uint32_t SIG_GPIO[6] = {
    0x52808008u, 0x331f1c28u, 0x7100503fu,
    0x5a9f9108u, 0x12003d00u, 0xd65f03c0u
};

/* Native D2207 GPIO mapper (9 instructions). */
static const uint32_t D2207_GPIO_CAVE[9] = {
    0x529fffe8u, 0x7100443fu, 0x32160029u, 0x0b01042au,
    0x110f814au, 0x1a8a3129u, 0x7100503fu, 0x1a898100u,
    0xd65f03c0u
};
#define GPIO_CAVE_WORDS 9

/*
 * Boost trampoline context: 7 words read from (patch_point - 20).
 * OFF_BOOST_PATCH is the byte distance from the mask anchor to the
 * "strb w8,[sp,#0x2f]" patch point inside _setLDO.  This is a structural
 * constant of the function and is verified by SIG_BOOST_CTX before patching.
 */
#define OFF_BOOST_PATCH 0x240u

static const uint32_t SIG_BOOST_CTX[7] = {
    0x39402929u, 0x0a290108u, 0x7100029fu, 0x1a9f1129u,
    0x2a090108u, 0x3900bfe8u, 0xf9400268u
};

/* The "strb w8,[sp,#0x2f]" instruction that is the patch point. */
#define INSN_STRB_PATCH  0x3900bfe8u
/* The branch-to-cave instruction written at the patch point. */
#define INSN_B_TO_CAVE   0x14000000u   /* B #0  — filled in at runtime */

/*
 * Boost cave body (without the final back-branch, which is computed at runtime).
 * 8 words total; slot [7] is computed and written separately.
 */
#define CAVE_BODY_WORDS 7
static const uint32_t BOOST_CAVE_BODY[CAVE_BODY_WORDS] = {
    0xd1003b29u,  /* sub  x9, x25, #0xe                                  */
    0xf100093fu,  /* cmp  x9, #2                                          */
    0x54000088u,  /* b.hi store          (not ldo15..17)                  */
    0x721e091fu,  /* tst  w8, #0x1c      (any of the 3 rails on?)         */
    0x54000040u,  /* b.eq store                                           */
    0x32000508u,  /* orr  w8, w8, #3     (shared boost enable)            */
    0x3900bfe8u,  /* store: strb w8,[sp,#0x2f]  (original insn)          */
    /* slot [7] = B back to patch_point+4, computed at runtime            */
};
#define CAVE_WORDS (CAVE_BODY_WORDS + 1)   /* 8 total */

/* Gap between the boost cave and GPIO cave (bytes). */
#define GPIO_CAVE_GAP  0x40u

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static int verbose;

static void die(const char *s)
{
    fprintf(stderr, "error: %s\n", s);
    exit(1);
}

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v; memcpy(&v, p, 4); return v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

/* Encode an AArch64 unconditional B from `from` VA to `to` VA. */
static uint32_t arm64_b(uint64_t from, uint64_t to)
{
    int64_t d = (int64_t)to - (int64_t)from;
    if ((d & 3) || d < -(1LL<<27) || d >= (1LL<<27))
        die("AArch64 branch out of range/alignment");
    return 0x14000000u | ((uint32_t)((d >> 2) & 0x03ffffffu));
}

static size_t count_bytes(const uint8_t *hay, size_t hlen,
                          const uint8_t *needle, size_t nlen, size_t *first)
{
    size_t n = 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && !memcmp(hay+i, needle, nlen)) {
            if (!n && first) *first = i;
            n++;
        }
    }
    return n;
}

static size_t count_words(const uint8_t *buf, size_t len,
                          const uint32_t *sig, size_t nw, size_t *first)
{
    size_t n = 0;
    for (size_t i = 0; i + 4*nw <= len; i += 4) {
        size_t k;
        for (k = 0; k < nw; k++)
            if (rd32(buf + i + 4*k) != sig[k]) break;
        if (k == nw) {
            if (!n && first) *first = i;
            n++;
        }
    }
    return n;
}

/* ── plist helpers ──────────────────────────────────────────────────────── */

static const char *find_str(const char *h, size_t hl, const char *n)
{
    size_t nl = strlen(n);
    if (!nl || hl < nl) return NULL;
    for (size_t i = 0; i+nl <= hl; i++)
        if (h[i]==n[0] && !memcmp(h+i,n,nl)) return h+i;
    return NULL;
}

static size_t count_str(const char *h, size_t hl, const char *n)
{
    size_t c=0, nl=strlen(n);
    for (size_t i=0; i+nl<=hl; i++)
        if (h[i]==n[0] && !memcmp(h+i,n,nl)) c++;
    return c;
}

static int find_kext_entry(const char *b, size_t len, const char *needle,
                           size_t *es, size_t *ee)
{
    int depth=0; size_t start=0;
    for (size_t i=0; i<len;) {
        if (b[i]!='<'){i++;continue;}
        size_t j=i; while(j<len&&b[j]!='>') j++;
        if (j>=len) break;
        int closing=(i+1<len&&b[i+1]=='/');
        const char *name=b+i+1+closing;
        if (!strncmp(name,"dict",4)&&(name[4]=='>'||name[4]==' '||name[4]=='/')) {
            int selfclose=(b[j-1]=='/');
            if (closing) {
                if (depth>0) depth--;
                if (depth==1) {
                    size_t end=j+1;
                    if (find_str(b+start,end-start,needle)) {
                        *es=start; *ee=end; return 1;
                    }
                }
            } else if (!selfclose) {
                depth++;
                if (depth==2) start=i;
            }
        }
        i=j+1;
    }
    return 0;
}

static size_t replace_same_len(char *b, size_t len, const char *from,
                               const char *to)
{
    size_t fl=strlen(from), c=0;
    if (fl!=strlen(to)) die("internal: replacement length mismatch");
    for (size_t i=0; i+fl<=len; i++) {
        if (b[i]==from[0]&&!memcmp(b+i,from,fl)) {
            memcpy(b+i,to,fl); c++; i+=fl-1;
        }
    }
    return c;
}

/* ── Kext Mach-O lookup ──────────────────────────────────────────────────── */

/*
 * Kernel VA → file offset, using the outer kernelcache's segment table.
 * We build this table in main() by walking the outer Mach-O's load commands.
 */
#define MAX_KSEGS 32
typedef struct { uint64_t va, size, foff; } kseg_t;
static kseg_t ksegs[MAX_KSEGS];
static int    nksegs = 0;

static void build_seg_table(const uint8_t *buf, size_t bufsz)
{
    uint32_t ncmds; memcpy(&ncmds, buf+16, 4);
    size_t off=32;
    for (uint32_t i=0; i<ncmds && nksegs<MAX_KSEGS; i++) {
        if (off+8>bufsz) break;
        uint32_t cmd,csz;
        memcpy(&cmd,buf+off,4); memcpy(&csz,buf+off+4,4);
        if (csz<8||off+csz>bufsz) break;
        if (cmd==LC_SEGMENT_64) {
            uint64_t vm,vs,fo;
            memcpy(&vm,buf+off+24,8); memcpy(&vs,buf+off+32,8);
            memcpy(&fo,buf+off+40,8);
            ksegs[nksegs].va=vm; ksegs[nksegs].size=vs; ksegs[nksegs].foff=fo;
            nksegs++;
        }
        off+=csz;
    }
}

static uint64_t kva_to_foff(uint64_t va)
{
    for (int i=0; i<nksegs; i++)
        if (va>=ksegs[i].va && va<ksegs[i].va+ksegs[i].size)
            return ksegs[i].foff+(va-ksegs[i].va);
    return UINT64_MAX;
}

/*
 * Find the D2186PMU kext's TEXT_EXEC end by:
 *   1. Parsing __PRELINK_INFO to find _PrelinkExecutableLoadAddr for
 *      com.apple.driver.AppleD2186PMU.
 *   2. Mapping that VA to a file offset to reach the embedded Mach-O.
 *   3. Walking the embedded Mach-O's LC_SEGMENT_64 commands for __TEXT_EXEC.
 *   4. Returning the VA and size of __TEXT_EXEC, which lets us compute the
 *      first zero-filled word after the kext's code.
 *
 * Returns 1 on success.
 */
static int find_d2186_text_exec(const uint8_t *buf, size_t bufsz,
                                uint64_t *text_va_out, uint64_t *text_sz_out)
{
    /* Locate __PRELINK_INFO */
    uint32_t ncmds; memcpy(&ncmds, buf+16, 4);
    size_t off=32;
    size_t info_foff=0, info_fsz=0;
    for (uint32_t i=0; i<ncmds; i++) {
        if (off+8>bufsz) die("truncated load commands");
        uint32_t cmd,csz;
        memcpy(&cmd,buf+off,4); memcpy(&csz,buf+off+4,4);
        if (csz<8||off+csz>bufsz) die("invalid load command");
        if (cmd==LC_SEGMENT_64 && !strncmp((char*)buf+off+8,"__PRELINK_INFO",16)) {
            uint64_t fo,fs;
            memcpy(&fo,buf+off+40,8); memcpy(&fs,buf+off+48,8);
            info_foff=(size_t)fo; info_fsz=(size_t)fs;
            break;
        }
        off+=csz;
    }
    if (!info_fsz || info_foff+info_fsz>bufsz) {
        fprintf(stderr,"error: __PRELINK_INFO not found\n"); return 0;
    }

    const char *info=(const char*)buf+info_foff;
    size_t used=info_fsz;
    while (used && info[used-1]=='\0') used--;

    /* Find the D2186PMU kext entry and extract _PrelinkExecutableLoadAddr */
    static const char D2_ID[] =
        "<key>CFBundleIdentifier</key>"
        "<string>com.apple.driver.AppleD2186PMU</string>";

    const char *hit = find_str(info, used, D2_ID);
    if (!hit) {
        fprintf(stderr,"error: AppleD2186PMU not found in __PRELINK_INFO\n");
        return 0;
    }

    /* Search ±16 KB for _PrelinkExecutableLoadAddr */
    size_t hit_off = (size_t)(hit - info);
    size_t win_start = hit_off > 16384 ? hit_off - 16384 : 0;
    size_t win_len   = used - win_start;
    if (win_len > 32768) win_len = 32768;

    const char *win = info + win_start;

    /* Find the integer value after the key */
    static const char LA_KEY[] = "<key>_PrelinkExecutableLoadAddr</key>";
    const char *la_p = find_str(win, win_len, LA_KEY);
    if (!la_p) {
        fprintf(stderr,"error: _PrelinkExecutableLoadAddr not found near D2186PMU entry\n");
        return 0;
    }
    la_p += strlen(LA_KEY);
    /* skip to '>' of <integer ...> */
    const char *gt = memchr(la_p, '>', (size_t)(win + win_len - la_p));
    if (!gt) { fprintf(stderr,"error: bad plist integer tag\n"); return 0; }
    la_p = gt + 1;
    char *endp;
    uint64_t load_addr = strtoull(la_p, &endp, 0);
    if (endp == la_p) { fprintf(stderr,"error: bad load addr value\n"); return 0; }

    printf("[*] AppleD2186PMU _PrelinkExecutableLoadAddr = 0x%llx\n",
           (unsigned long long)load_addr);

    /* Map load_addr to file offset (kext header is in __PRELINK_TEXT). */
    uint64_t kext_foff = kva_to_foff(load_addr);
    if (kext_foff==UINT64_MAX) {
        fprintf(stderr,"error: cannot map D2186PMU load addr to file offset\n");
        return 0;
    }
    if (kext_foff+64>bufsz) {
        fprintf(stderr,"error: D2186PMU kext header outside file\n");
        return 0;
    }

    /* Parse the embedded kext Mach-O */
    const uint8_t *kext = buf + kext_foff;
    uint32_t kmagic; memcpy(&kmagic, kext, 4);
    if (kmagic != MH_MAGIC_64) {
        fprintf(stderr,"error: D2186PMU kext Mach-O bad magic %#x\n", kmagic);
        return 0;
    }
    uint32_t kncmds; memcpy(&kncmds, kext+16, 4);
    size_t koff = 32;
    for (uint32_t i=0; i<kncmds; i++) {
        if (koff+8>0x10000) break;
        uint32_t kcmd,kcsz;
        memcpy(&kcmd,kext+koff,4); memcpy(&kcsz,kext+koff+4,4);
        if (kcsz<8||koff+kcsz>0x10000) break;
        if (kcmd==LC_SEGMENT_64) {
            char segname[17];
            memcpy(segname, kext+koff+8, 16); segname[16]='\0';
            if (!strncmp(segname,"__TEXT_EXEC",16)) {
                uint64_t vm,vs;
                memcpy(&vm,kext+koff+24,8); memcpy(&vs,kext+koff+32,8);
                *text_va_out  = vm;
                *text_sz_out  = vs;
                printf("[*] AppleD2186PMU __TEXT_EXEC VA=0x%llx size=0x%llx\n",
                       (unsigned long long)vm, (unsigned long long)vs);
                return 1;
            }
        }
        koff+=kcsz;
    }

    fprintf(stderr,"error: AppleD2186PMU __TEXT_EXEC segment not found in kext Mach-O\n");
    return 0;
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int dry=0, keep_rtc=1, no_boost=0, ai=1;

    while (ai<argc && argv[ai][0]=='-' && argv[ai][1]) {
        if      (!strcmp(argv[ai],"-n")) dry=1;
        else if (!strcmp(argv[ai],"-k")) keep_rtc=1;
        else if (!strcmp(argv[ai],"-K")) keep_rtc=0;
        else if (!strcmp(argv[ai],"-B")) no_boost=1;
        else if (!strcmp(argv[ai],"-v")) verbose=1;
        else { fprintf(stderr,"unknown option %s\n",argv[ai]); return 2; }
        ai++;
    }
    if (argc-ai<1||argc-ai>2) {
        fprintf(stderr,"usage: %s [-n] [-k] [-K] [-B] [-v] in.raw [out.raw]\n",
                argv[0]); return 2;
    }

    const char *inpath=argv[ai];
    char outbuf[4096]; const char *outpath;
    if (argc-ai==2) outpath=argv[ai+1];
    else { snprintf(outbuf,sizeof(outbuf),"%s.pmu",inpath); outpath=outbuf; }

    FILE *f=fopen(inpath,"rb");
    if (!f) die("cannot open input");
    if (fseek(f,0,SEEK_END)) die("fseek failed");
    long fsz=ftell(f);
    if (fsz<32) die("file too small");
    if (fseek(f,0,SEEK_SET)) die("fseek failed");
    uint8_t *buf=malloc((size_t)fsz);
    if (!buf) die("out of memory");
    if (fread(buf,1,(size_t)fsz,f)!=(size_t)fsz) die("read failed");
    fclose(f);

    uint32_t hdr[8]; memcpy(hdr,buf,sizeof(hdr));
    if (hdr[0]!=MH_MAGIC_64) die("not a 64-bit little-endian Mach-O");

    /* Build the kernel VA→file-offset table. */
    build_seg_table(buf,(size_t)fsz);

    /* ---- Locate __PRELINK_INFO ---- */
    size_t off=32, info_off=0, info_sz=0;
    for (uint32_t i=0; i<hdr[4]; i++) {
        if (off+8>(size_t)fsz) die("truncated load commands");
        uint32_t cmd,csz;
        memcpy(&cmd,buf+off,4); memcpy(&csz,buf+off+4,4);
        if (csz<8||off+csz>(size_t)fsz) die("invalid load command size");
        if (cmd==LC_SEGMENT_64 &&
            !strncmp((char*)buf+off+8,"__PRELINK_INFO",16)) {
            uint64_t fo,fs;
            memcpy(&fo,buf+off+40,8); memcpy(&fs,buf+off+48,8);
            info_off=(size_t)fo; info_sz=(size_t)fs; break;
        }
        off+=csz;
    }
    if (!info_sz||info_off+info_sz>(size_t)fsz)
        die("__PRELINK_INFO segment not found / outside file");

    char *info=(char*)buf+info_off;
    size_t used=info_sz;
    while (used&&info[used-1]=='\0') used--;

    /* ---- Identify AppleD2186PMU plist entry ---- */
    size_t es,ee;
    if (!find_kext_entry(info,used,
            "<key>CFBundleIdentifier</key>"
            "<string>com.apple.driver.AppleD2186PMU</string>",&es,&ee))
        die("AppleD2186PMU prelink entry not found (is this the tvOS kernel?)");

    printf("AppleD2186PMU prelink entry: info+0x%zx..0x%zx\n",es,ee);

    char *ent=info+es; size_t elen=ee-es;

    static const char M_OLD[]="<key>IONameMatch</key><string>pmu,d2186</string>";
    static const char M_NEW[]="<key>IONameMatch</key><string>pmu,d2207</string>";
    static const char P_OLD[]="<key>IOProviderClass</key><string>AppleD2186PMU</string>";
    static const char P_NEW[]="<key>IOProviderClass</key><string>AppleD2186PMX</string>";

    int plist_done=(count_str(ent,elen,M_NEW)==1&&count_str(ent,elen,M_OLD)==0);

    /* ---- Find D2186PMU TEXT_EXEC dynamically ---- */
    uint64_t d2_text_va=0, d2_text_sz=0;
    if (!find_d2186_text_exec(buf,(size_t)fsz,&d2_text_va,&d2_text_sz))
        die("Cannot locate AppleD2186PMU __TEXT_EXEC");

    uint64_t d2_text_foff = kva_to_foff(d2_text_va);
    if (d2_text_foff==UINT64_MAX)
        die("Cannot map AppleD2186PMU TEXT_EXEC VA to file offset");

    /* ---- Code / data signatures ---- */
    size_t tab_at=0, msk_at=0, gpio_at=0;
    size_t n_tab_old = count_bytes(buf,(size_t)fsz,
                                   D2186_LDO_TABLE,LDO_BYTES,&tab_at);
    size_t n_tab_new = count_bytes(buf,(size_t)fsz,
                                   D2207_LDO_TABLE,LDO_BYTES,NULL);
    size_t n_msk  = count_words(buf,(size_t)fsz,SIG_MASKS,6,&msk_at);
    size_t n_gpio = count_words(buf,(size_t)fsz,SIG_GPIO,6,&gpio_at);

    int tab_done=(n_tab_old==0&&n_tab_new>=1);

    printf("signatures: D2186 ldo table x%zu, D2207 table x%zu, "
           "mask anchor x%zu, gpio map x%zu\n",
           n_tab_old,n_tab_new,n_msk,n_gpio);

    if (!tab_done&&n_tab_old!=1)
        die("D2186 LDO table signature not unique/found; refusing");

    /* Tolerate already-patched mask sequence. */
    if (n_msk!=1) {
        uint32_t pat[6]={NEW_MASK_A_LO,NEW_MASK_A_HI,SIG_MASKS[2],
                         SIG_MASKS[3],NEW_MASK_B,SIG_MASKS[5]};
        if (count_words(buf,(size_t)fsz,pat,6,NULL)==1&&tab_done)
            printf("_setLDO masks already patched.\n");
        else
            die("_setLDO mask signature not unique/found; refusing");
    }

    /* Anchor = start of (original or already-patched) mask sequence. */
    size_t anchor_at=msk_at;
    if (n_msk!=1) {
        uint32_t pat[6]={NEW_MASK_A_LO,NEW_MASK_A_HI,SIG_MASKS[2],
                         SIG_MASKS[3],NEW_MASK_B,SIG_MASKS[5]};
        if (count_words(buf,(size_t)fsz,pat,6,&anchor_at)!=1)
            die("mask anchor lost");
    }

    /*
     * Cave placement: immediately after the kext's __TEXT_EXEC.
     * The PLK_TEXT_EXEC segment has zero-fill padding after each kext's
     * code, which we use as scratch space.
     *
     * boost cave  = first 4-word-aligned address at or after TEXT_EXEC end
     * GPIO cave   = boost cave + GPIO_CAVE_GAP
     *
     * We verify both regions are zero-filled before writing.
     */
    uint64_t text_exec_end_va   = d2_text_va + d2_text_sz;
    uint64_t text_exec_end_foff = kva_to_foff(text_exec_end_va);
    if (text_exec_end_foff==UINT64_MAX)
        die("Cannot map D2186PMU TEXT_EXEC end VA to file offset");

    /* Align to 16-byte (4-instruction) boundary. */
    text_exec_end_foff = (text_exec_end_foff + 15) & ~(size_t)15;

    size_t bc = (size_t)text_exec_end_foff;          /* boost cave foff  */
    size_t gc = bc + GPIO_CAVE_GAP;                   /* GPIO  cave foff  */

    size_t cave_need = (size_t)(GPIO_CAVE_GAP + 4*GPIO_CAVE_WORDS);
    if (bc + cave_need > (size_t)fsz)
        die("cave region outside file");

    /* Boost patch point: anchor + OFF_BOOST_PATCH */
    size_t bp = anchor_at + OFF_BOOST_PATCH;

    /*
     * We need the VA of the cave to compute the B instruction at the patch
     * point, and the VA of the patch point to compute the back-branch from
     * the cave.  Derive both from the kernel's segment table.
     */

    /* Find which kernel segment contains the anchor (PLK_TEXT_EXEC). */
    uint64_t plk_vm=0, plk_fo=0;
    for (int i=0; i<nksegs; i++) {
        if (anchor_at>=ksegs[i].foff &&
            anchor_at< ksegs[i].foff+ksegs[i].size) {
            plk_vm=ksegs[i].va; plk_fo=ksegs[i].foff; break;
        }
    }
    if (!plk_vm) die("cannot map anchor into a kernel segment");

    uint64_t bp_va = plk_vm + (bp - plk_fo);
    uint64_t bc_va = plk_vm + (bc - plk_fo);
    uint64_t gc_va = plk_vm + (gc - plk_fo);

    /* GPIO site VA */
    uint64_t gp_va = plk_vm + (gpio_at - plk_fo);

    printf("[*] boost cave: foff=0x%zx VA=0x%llx\n",
           bc,(unsigned long long)bc_va);
    printf("[*] GPIO  cave: foff=0x%zx VA=0x%llx\n",
           gc,(unsigned long long)gc_va);

    /* Compute branch instructions (all relative, so correct regardless of KASLR). */
    uint32_t b_patch_to_cave = arm64_b(bp_va, bc_va);
    uint32_t b_cave_back      = arm64_b(bc_va + (CAVE_BODY_WORDS)*4, bp_va + 4);
    uint32_t gpio_branch       = arm64_b(gp_va, gc_va);

    /* ---- Idempotency checks ---- */
    int gpio_done   = (n_gpio == 0);
    int boost_done  = 0;
    int boost_todo  = 0;

    if (!no_boost) {
        if (bc + 4*CAVE_WORDS + GPIO_CAVE_GAP + 4*GPIO_CAVE_WORDS > (size_t)fsz)
            die("cave outside file");
        if (rd32(buf+bp) == b_patch_to_cave) {
            /* Already patched; verify cave content. */
            for (int i=0; i<CAVE_BODY_WORDS; i++)
                if (rd32(buf+bc+4*i) != BOOST_CAVE_BODY[i])
                    die("boost patch present but cave content unexpected");
            if (rd32(buf+bc+4*CAVE_BODY_WORDS) != b_cave_back)
                die("boost cave back-branch mismatch (different kernel?)");
            boost_done=1;
        } else if (rd32(buf+bp) == INSN_STRB_PATCH) {
            /* Verify context before touching. */
            for (size_t i=0; i<7; i++)
                if (rd32(buf+bp-20+4*i) != SIG_BOOST_CTX[i])
                    die("boost patch point context mismatch; refusing");
            /* Verify cave is zero-filled. */
            for (size_t i=0; i<4*CAVE_WORDS+GPIO_CAVE_GAP; i++)
                if (buf[bc+i])
                    die("boost cave is not zero-filled; refusing");
            boost_todo=1;
        } else {
            die("boost patch point: unexpected instruction (wrong kernel or already modified)");
        }
    }

    if (gpio_done) {
        if (rd32(buf+gpio_at) != gpio_branch)
            die("gpio patch present but branch instruction unexpected");
        for (int i=0; i<GPIO_CAVE_WORDS; i++)
            if (rd32(buf+gc+4*i) != D2207_GPIO_CAVE[i])
                die("gpio cave content unexpected");
    } else {
        for (size_t i=0; i<6; i++)
            if (rd32(buf+gpio_at+4*i) != SIG_GPIO[i])
                die("gpio signature changed; refusing");
        for (size_t i=0; i<4*GPIO_CAVE_WORDS; i++)
            if (buf[gc+i])
                die("gpio cave not zero-filled; refusing");
    }

    if (plist_done&&tab_done&&n_msk==0&&n_gpio==0&&(no_boost||boost_done)) {
        printf("Already fully patched. Nothing to do.\n");
        free(buf); return 0;
    }

    /* ---- [1] plist: IONameMatch ---- */
    if (!plist_done) {
        if (count_str(ent,elen,M_OLD)!=1)
            die("expected exactly one pmu,d2186 IONameMatch");
        replace_same_len(ent,elen,M_OLD,M_NEW);
        printf("[1] IONameMatch pmu,d2186 -> pmu,d2207\n");
    } else {
        printf("[1] IONameMatch already pmu,d2207\n");
    }

    if (!keep_rtc) {
        size_t c=count_str(ent,elen,P_OLD);
        if (c==2) {
            replace_same_len(ent,elen,P_OLD,P_NEW);
            printf("[6] RTC + watchdog personalities disabled\n");
        } else if (c==0&&count_str(ent,elen,P_NEW)==2) {
            printf("[6] RTC + watchdog already disabled\n");
        } else {
            die("unexpected IOProviderClass layout");
        }
    } else {
        printf("[6] -k: RTC + watchdog left enabled\n");
    }

    /* ---- [2] LDO table ---- */
    if (!tab_done) {
        memcpy(buf+tab_at, D2207_LDO_TABLE, LDO_BYTES);
        printf("[2] LDO table @file+0x%zx: %d rows -> D2207\n",tab_at,LDO_ROWS);
        if (verbose)
            for (int r=0; r<LDO_ROWS; r++)
                if (memcmp(D2186_LDO_TABLE+r*12,D2207_LDO_TABLE+r*12,12))
                    printf("      ldo%-2d row changed\n",r+1);
    } else {
        printf("[2] LDO table already D2207\n");
    }

    /* ---- [3][4] masks + 0x391 ---- */
    if (n_msk==1) {
        wr32(buf+msk_at+0,  NEW_MASK_A_LO);
        wr32(buf+msk_at+4,  NEW_MASK_A_HI);
        wr32(buf+msk_at+16, NEW_MASK_B);
        printf("[3] _setLDO masks @file+0x%zx patched\n",msk_at);

        size_t lo=msk_at>0x80?msk_at-0x80:0;
        size_t hi=msk_at+0x400; if (hi>(size_t)fsz) hi=(size_t)fsz;
        int hits=0;
        for (size_t p=lo&~3u; p+4<=hi; p+=4)
            if (rd32(buf+p)==OLD_MOV_W1_380) {
                if (verbose) printf("      0x380->0x391 @file+0x%zx\n",p);
                wr32(buf+p,NEW_MOV_W1_391); hits++;
            }
        if (hits!=2) die("expected exactly 2 'mov w1,#0x380'");
        printf("[4] special-case register 0x380 -> 0x391 (x2)\n");
    } else {
        printf("[3][4] _setLDO already patched\n");
    }

    /* ---- [5] GPIO trampoline ---- */
    if (n_gpio==1) {
        for (int i=0; i<GPIO_CAVE_WORDS; i++)
            wr32(buf+gc+4*i, D2207_GPIO_CAVE[i]);
        wr32(buf+gpio_at, gpio_branch);
        for (int i=1; i<6; i++) wr32(buf+gpio_at+4*i, 0xd503201fu); /* nop */
        printf("[5] GPIO map @file+0x%zx -> D2207 cave @file+0x%zx\n",
               gpio_at,gc);
        if (verbose)
            printf("      VA 0x%016llx -> 0x%016llx, branch 0x%08x\n",
                   (unsigned long long)gp_va,
                   (unsigned long long)gc_va, gpio_branch);
    } else {
        printf("[5] D2207 GPIO mapper already installed\n");
    }

    /* ---- [7] 5 V boost trampoline ---- */
    if (boost_todo) {
        for (int i=0; i<CAVE_BODY_WORDS; i++)
            wr32(buf+bc+4*i, BOOST_CAVE_BODY[i]);
        wr32(buf+bc+4*CAVE_BODY_WORDS, b_cave_back);   /* back-branch (dynamic) */
        wr32(buf+bp, b_patch_to_cave);                  /* patch point -> cave   */
        printf("[7] 5V boost: patch @file+0x%zx -> cave @file+0x%zx "
               "(branch 0x%08x, back 0x%08x)\n",
               bp, bc, b_patch_to_cave, b_cave_back);
    } else if (boost_done) {
        printf("[7] 5V boost trampoline already installed\n");
    } else {
        printf("[7] -B: 5V boost skipped\n");
    }

    /* ---- post-patch verification ---- */
    if (count_bytes(buf,(size_t)fsz,D2207_LDO_TABLE,LDO_BYTES,NULL)<1)
        die("post-patch: D2207 LDO table not present");
    {
        uint32_t pat[6]={NEW_MASK_A_LO,NEW_MASK_A_HI,SIG_MASKS[2],
                         SIG_MASKS[3],NEW_MASK_B,SIG_MASKS[5]};
        if (count_words(buf,(size_t)fsz,pat,6,NULL)!=1)
            die("post-patch: mask sequence verification failed");
    }
    if (count_str(ent,elen,M_NEW)!=1)
        die("post-patch: pmu,d2207 match missing");
    if (rd32(buf+gpio_at)!=gpio_branch)
        die("post-patch: GPIO branch verification failed");
    for (int i=0; i<GPIO_CAVE_WORDS; i++)
        if (rd32(buf+gc+4*i)!=D2207_GPIO_CAVE[i])
            die("post-patch: GPIO cave verification failed");
    if (!no_boost) {
        if (rd32(buf+bp)!=b_patch_to_cave)
            die("post-patch: boost branch verification failed");
        if (rd32(buf+bc+4*CAVE_BODY_WORDS)!=b_cave_back)
            die("post-patch: boost back-branch verification failed");
    }

    printf("Verified: pmu,d2207 match, D2207 LDO table, masks, GPIO guard%s.\n",
           no_boost?"":", 5V boost");
    printf("\nLimits: ldo21+ rejected; 5V boost is set-only; D2207 backlight/"
           "WLED/LCM, IDAC, and charger input-current code remain absent.\n");

    if (dry) {
        printf("Dry run; nothing written.\n");
        free(buf); return 0;
    }

    f=fopen(outpath,"wb");
    if (!f) die("cannot open output");
    if (fwrite(buf,1,(size_t)fsz,f)!=(size_t)fsz) { fclose(f); die("write failed"); }
    fclose(f);
    printf("Wrote %s\n",outpath);
    free(buf);
    return 0;
}
