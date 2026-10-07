/*
 * pmupatch_d2207.c
 *
 * Targeted "PMU for touch" patch for an Apple TV (tvOS 16.0b2, A8/t7000)
 * prelinked kernelcache that is being used to boot an iPad mini 4 (J96).
 *
 * Problem
 * -------
 * The tvOS kernelcache only contains AppleD2186PMU, which matches the
 * device-tree node "pmu,d2186".  The iPad mini 4 has "pmu,d2207", so no PMU
 * driver attaches and none of the PMU-published function-* handlers (LDO,
 * GPIO, ...) exist.  AppleMultitouchSPI resolves function-power_ldo/ana/mamba
 * from those handlers; without them setPowerEnabled() returns
 * kIOReturnUnsupported and the touch analog rails are never switched on.
 *
 * What this patch does (all edits are in place and the same size)
 * ----------------------------------------------------------------
 *  1. __PRELINK_INFO: AppleD2186PMU personality IONameMatch
 *         pmu,d2186 -> pmu,d2207
 *  2. AppleD2186PMU::_setLDO table: rows 0..19 replaced with the real
 *     AppleD2207PMU rows (copied byte-for-byte from the iOS 15.8.8 kernel).
 *  3. AppleD2186PMU::_setLDO classification masks:
 *       "no-voltage-register" mask   0xfe800  -> 0x7e0800   (2 insns)
 *       "voltage-adjustable"  mask   0x17ff   -> 0x1ffff    (1 insn;
 *           bit 11 is already caught by the first mask, so this is
 *           equivalent to D2207's 0x1f7ff)
 *  4. AppleD2186PMU::_setLDO special-case register  0x380 -> 0x391 (x2)
 *  5. PMU GPIO number->register map (vtable slot 0x660) made FAIL-CLOSED:
 *       returns 0xffff, so every table-driven PMU GPIO access is rejected
 *       instead of being written with D2186's (different) register map.
 *  6. (default) AppleD2186PMURTC / AppleD2186PMUWatchDogTimer personalities
 *     get an unmatchable provider class, so their D2186 register layout is
 *     never applied to D2207 silicon.  Use -k to keep them.
 *  7. (default) 5 V rail boost: D2207's _setLDO ORs bits 0..1 into the shared
 *     enable register 0x84 whenever ldo15..17 (idx 14..16) is enabled.  A
 *     9-instruction trampoline in the zero-filled gap after the kext's
 *     __TEXT_EXEC reproduces that (set-only, it never clears the boost).
 *     Use -B to skip it.
 *
 * Known limits (printed again at run time)
 * ----------------------------------------
 *  - LDO index >= 20 (ldo21..23) is rejected: the D2186 table has no room.
 *  - The 5 V boost is set-only; D2207 also clears it when the last 5 V rail
 *    goes off (state cached in an object field whose layout differs here).
 *  - PMU GPIO functions are intentionally unavailable (see 5).
 *  - Backlight/WLED/LCM, IDAC, charger input-current code of D2207 is absent.
 *
 * Usage:
 *   cc -O2 -Wall -Wextra -o pmupatch_d2207 pmupatch_d2207.c
 *   ./pmupatch_d2207 [-n] [-k] [-B] [-v] in.raw [out.raw]
 *
 *   -n  dry run (find and verify everything, write nothing)
 *   -k  keep the RTC and watchdog personalities enabled
 *   -B  do not install the 5 V boost trampoline
 *   -v  print every patched word / byte range
 *
 * The tool is idempotent and refuses to patch anything it cannot positively
 * identify (every signature must match exactly once).  It does not re-sign
 * the kernelcache.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MH_MAGIC_64   0xfeedfacfu
#define LC_SEGMENT_64 0x19u

/* ------------------------------------------------------------------ */
/* Real table bytes.  Row = 12 bytes:                                  */
/*  u16 min_mV, u8 step_mV, u8 max_code, u8 vmask, u8 special_en_mask,  */
/*  u16 vreg, u16 enreg, u8 enbit, u8 pad                               */
/* ------------------------------------------------------------------ */
static const uint8_t D2186_LDO_TABLE[240] = {
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x08, 0x03, 0x82, 0x00, 0x02, 0x00,   /* ldo1  min=1200mV step=25mV n=0x7f vreg=0x308 en=0x82/0x02 */
    0xb0, 0x04, 0x05, 0xff, 0xff, 0x04, 0x10, 0x03, 0x82, 0x00, 0x04, 0x00,   /* ldo2  min=1200mV step=5mV n=0xff vreg=0x310 en=0x82/0x04 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x18, 0x03, 0x82, 0x00, 0x08, 0x00,   /* ldo3  min=1200mV step=25mV n=0x7f vreg=0x318 en=0x82/0x08 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x20, 0x03, 0x82, 0x00, 0x10, 0x00,   /* ldo4  min=1200mV step=25mV n=0x7f vreg=0x320 en=0x82/0x10 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x28, 0x03, 0x82, 0x00, 0x20, 0x00,   /* ldo5  min=1200mV step=25mV n=0x7f vreg=0x328 en=0x82/0x20 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x40, 0x30, 0x03, 0x82, 0x00, 0x40, 0x00,   /* ldo6  min=1200mV step=25mV n=0x7f vreg=0x330 en=0x82/0x40 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x38, 0x03, 0x82, 0x00, 0x80, 0x00,   /* ldo7  min=1200mV step=25mV n=0x7f vreg=0x338 en=0x82/0x80 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x40, 0x03, 0x83, 0x00, 0x01, 0x00,   /* ldo8  min=1200mV step=25mV n=0x7f vreg=0x340 en=0x83/0x01 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x48, 0x03, 0x83, 0x00, 0x02, 0x00,   /* ldo9  min=1200mV step=25mV n=0x7f vreg=0x348 en=0x83/0x02 */
    0x58, 0x02, 0x0c, 0xff, 0xff, 0x00, 0x50, 0x03, 0x83, 0x00, 0x04, 0x00,   /* ldo10 min=600mV step=12mV n=0xff vreg=0x350 en=0x83/0x04 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x58, 0x03, 0x83, 0x00, 0x08, 0x00,   /* ldo11 min=1200mV step=25mV n=0x7f vreg=0x358 en=0x83/0x08 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00,   /* ldo12 (no vreg) en=0x83/0x00 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x68, 0x03, 0x83, 0x00, 0x20, 0x00,   /* ldo13 min=1200mV step=25mV n=0x7f vreg=0x368 en=0x83/0x20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x01, 0x00,   /* ldo14 (no vreg) en=0x85/0x01 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x02, 0x00,   /* ldo15 (no vreg) en=0x85/0x02 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x04, 0x00,   /* ldo16 (no vreg) en=0x85/0x04 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x10, 0x00,   /* ldo17 (no vreg) en=0x85/0x10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x20, 0x00,   /* ldo18 (no vreg) en=0x85/0x20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x00, 0x40, 0x00,   /* ldo19 (no vreg) en=0x92/0x40 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00,   /* ldo20 (no vreg) en=0x80/0x40 */
};

static const uint8_t D2207_LDO_TABLE[240] = {
    0xc4, 0x09, 0x19, 0x7f, 0x7f, 0x00, 0x08, 0x03, 0x82, 0x00, 0x02, 0x00,   /* ldo1  min=2500mV step=25mV n=0x7f vreg=0x308 en=0x82/0x02 */
    0xb0, 0x04, 0x05, 0xff, 0xff, 0x04, 0x10, 0x03, 0x82, 0x00, 0x04, 0x00,   /* ldo2  min=1200mV step=5mV n=0xff vreg=0x310 en=0x82/0x04 */
    0xc4, 0x09, 0x19, 0x7f, 0x7f, 0x00, 0x18, 0x03, 0x82, 0x00, 0x08, 0x00,   /* ldo3  min=2500mV step=25mV n=0x7f vreg=0x318 en=0x82/0x08 */
    0xc4, 0x09, 0x19, 0x7f, 0x7f, 0x00, 0x20, 0x03, 0x82, 0x00, 0x10, 0x00,   /* ldo4  min=2500mV step=25mV n=0x7f vreg=0x320 en=0x82/0x10 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x28, 0x03, 0x82, 0x00, 0x20, 0x00,   /* ldo5  min=1200mV step=25mV n=0x7f vreg=0x328 en=0x82/0x20 */
    0xc4, 0x09, 0x19, 0x7f, 0x7f, 0x40, 0x30, 0x03, 0x82, 0x00, 0x40, 0x00,   /* ldo6  min=2500mV step=25mV n=0x7f vreg=0x330 en=0x82/0x40 */
    0xa4, 0x06, 0x19, 0x7f, 0x7f, 0x00, 0x38, 0x03, 0x82, 0x00, 0x80, 0x00,   /* ldo7  min=1700mV step=25mV n=0x7f vreg=0x338 en=0x82/0x80 */
    0xa4, 0x06, 0x19, 0x7f, 0x7f, 0x00, 0x40, 0x03, 0x83, 0x00, 0x01, 0x00,   /* ldo8  min=1700mV step=25mV n=0x7f vreg=0x340 en=0x83/0x01 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x48, 0x03, 0x83, 0x00, 0x02, 0x00,   /* ldo9  min=1200mV step=25mV n=0x7f vreg=0x348 en=0x83/0x02 */
    0x58, 0x02, 0x19, 0xff, 0xff, 0x00, 0x50, 0x03, 0x83, 0x00, 0x04, 0x00,   /* ldo10 min=600mV step=25mV n=0xff vreg=0x350 en=0x83/0x04 */
    0xa4, 0x06, 0x19, 0x7f, 0x7f, 0x00, 0x58, 0x03, 0x83, 0x00, 0x08, 0x00,   /* ldo11 min=1700mV step=25mV n=0x7f vreg=0x358 en=0x83/0x08 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00,   /* ldo12 (no vreg) en=0x83/0x00 */
    0xa4, 0x06, 0x19, 0x7f, 0x7f, 0x00, 0x68, 0x03, 0x83, 0x00, 0x20, 0x00,   /* ldo13 min=1700mV step=25mV n=0x7f vreg=0x368 en=0x83/0x20 */
    0xb0, 0x04, 0x19, 0x7f, 0x7f, 0x00, 0x70, 0x03, 0x83, 0x00, 0x40, 0x00,   /* ldo14 min=1200mV step=25mV n=0x7f vreg=0x370 en=0x83/0x40 */
    0x88, 0x13, 0x32, 0x1f, 0x1f, 0x00, 0x98, 0x03, 0x84, 0x00, 0x04, 0x00,   /* ldo15 min=5000mV step=50mV n=0x1f vreg=0x398 en=0x84/0x04 */
    0x88, 0x13, 0x32, 0x1f, 0x1f, 0x00, 0x98, 0x03, 0x84, 0x00, 0x08, 0x00,   /* ldo16 min=5000mV step=50mV n=0x1f vreg=0x398 en=0x84/0x08 */
    0x88, 0x13, 0x32, 0x1f, 0x1f, 0x00, 0x98, 0x03, 0x84, 0x00, 0x10, 0x00,   /* ldo17 min=5000mV step=50mV n=0x1f vreg=0x398 en=0x84/0x10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x01, 0x00,   /* ldo18 (no vreg) en=0x85/0x01 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x02, 0x00,   /* ldo19 (no vreg) en=0x85/0x02 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x04, 0x00,   /* ldo20 (no vreg) en=0x85/0x04 */
};

#define LDO_ROWS   20
#define LDO_BYTES  (LDO_ROWS * 12)

/* AArch64 words (little endian) used as signatures / replacements. */
/* _setLDO, D2186: movz w8,#0xe800 ; movk w8,#0xf,lsl16 ; lsr x8,x8,x25
 *                 tbnz w8,#0,.. ; mov w8,#0x17ff ; lsr x8,x8,x25         */
static const uint32_t SIG_MASKS[6] = {
    0x529d0008u, 0x72a001e8u, 0x9ad92508u, 0x37000088u, 0x5282ffe8u,
    0x9ad92508u
};
#define NEW_MASK_A_LO  0x52810008u  /* movz w8,#0x800            */
#define NEW_MASK_A_HI  0x72a00fc8u  /* movk w8,#0x7e,lsl16       */
#define NEW_MASK_B     0x320043e8u  /* mov  w8,#0x1ffff (orr imm)*/

#define OLD_MOV_W1_380 0x52807001u  /* mov w1,#0x380 */
#define NEW_MOV_W1_391 0x52807221u  /* mov w1,#0x391 */

/* D2186 gpio->reg map: mov w8,#0x400; bfi w8,w1,#1,#8; cmp w1,#0x14;
 *                      csinv w8,w8,wzr,ls; and w0,w8,#0xffff; ret       */
static const uint32_t SIG_GPIO[6] = {
    0x52808008u, 0x331f1c28u, 0x7100503fu, 0x5a9f9108u, 0x12003d00u,
    0xd65f03c0u
};
#define NEW_MOV_W0_FFFF 0x529fffe0u
#define NEW_RET         0xd65f03c0u

/* 5 V boost trampoline.  Offsets are relative to the _setLDO mask anchor
 * (SIG_MASKS), which is unique.  Patch point = the "strb w8,[sp,#0x2f]" that
 * stores the new enable-register value; cave = zero gap after the kext.     */
#define OFF_BOOST_PATCH  0x240u     /* anchor + 0x240  (0x...15a8)          */
#define OFF_BOOST_CAVE   0x51bcu    /* anchor + 0x51bc (0x...26524)         */
#define CAVE_WORDS       8
/* original context: ldrb w9,[x9,#10]; bic; cmp w20,#0; csel; orr; strb; ldr */
static const uint32_t SIG_BOOST_CTX[7] = {
    0x39402929u, 0x0a290108u, 0x7100029fu, 0x1a9f1129u, 0x2a090108u,
    0x3900bfe8u, 0xf9400268u
};
#define BOOST_BRANCH_TO_CAVE 0x140013dfu   /* b cave                       */
static const uint32_t BOOST_CAVE[CAVE_WORDS] = {
    0xd1003b29u,  /* sub  x9, x25, #0xe       ; idx - 14                  */
    0xf100093fu,  /* cmp  x9, #2                                          */
    0x54000088u,  /* b.hi store               ; not ldo15..17             */
    0x721e091fu,  /* tst  w8, #0x1c           ; any of the 3 rails on?    */
    0x54000040u,  /* b.eq store                                           */
    0x32000508u,  /* orr  w8, w8, #3          ; shared boost enable       */
    0x3900bfe8u,  /* store: strb w8,[sp,#0x2f]  (the original insn)       */
    0x17ffec1bu   /* b    patch_point + 4                                 */
};

static int verbose;

static void die(const char *s)
{
    fprintf(stderr, "error: %s\n", s);
    exit(1);
}

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

/* Count occurrences of needle in hay; remember the first one. */
static size_t count_bytes(const uint8_t *hay, size_t hlen,
                          const uint8_t *needle, size_t nlen, size_t *first)
{
    size_t n = 0;
    if (!nlen || hlen < nlen)
        return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && !memcmp(hay + i, needle, nlen)) {
            if (!n && first)
                *first = i;
            n++;
        }
    }
    return n;
}

/* Count aligned occurrences of a word sequence. */
static size_t count_words(const uint8_t *buf, size_t len,
                          const uint32_t *sig, size_t nw, size_t *first)
{
    size_t n = 0;
    for (size_t i = 0; i + 4 * nw <= len; i += 4) {
        size_t k;
        for (k = 0; k < nw; k++)
            if (rd32(buf + i + 4 * k) != sig[k])
                break;
        if (k == nw) {
            if (!n && first)
                *first = i;
            n++;
        }
    }
    return n;
}

/* ---------------- plist helpers (text based, like mtpatch_j96) ------- */

static const char *find_str(const char *h, size_t hl, const char *n)
{
    size_t nl = strlen(n);
    if (!nl || hl < nl)
        return NULL;
    for (size_t i = 0; i + nl <= hl; i++)
        if (h[i] == n[0] && !memcmp(h + i, n, nl))
            return h + i;
    return NULL;
}

static size_t count_str(const char *h, size_t hl, const char *n)
{
    size_t c = 0, nl = strlen(n);
    for (size_t i = 0; i + nl <= hl; i++)
        if (h[i] == n[0] && !memcmp(h + i, n, nl))
            c++;
    return c;
}

/* Locate the top-level kext <dict> that contains `needle`. */
static int find_kext_entry(const char *b, size_t len, const char *needle,
                           size_t *es, size_t *ee)
{
    int depth = 0;
    size_t start = 0;

    for (size_t i = 0; i < len;) {
        if (b[i] != '<') {
            i++;
            continue;
        }
        size_t j = i;
        while (j < len && b[j] != '>')
            j++;
        if (j >= len)
            break;

        int closing = (i + 1 < len && b[i + 1] == '/');
        const char *name = b + i + 1 + closing;

        if (!strncmp(name, "dict", 4) &&
            (name[4] == '>' || name[4] == ' ' || name[4] == '/')) {
            int selfclose = (b[j - 1] == '/');
            if (closing) {
                if (depth > 0)
                    depth--;
                if (depth == 1) {
                    size_t end = j + 1;
                    if (find_str(b + start, end - start, needle)) {
                        *es = start;
                        *ee = end;
                        return 1;
                    }
                }
            } else if (!selfclose) {
                depth++;
                if (depth == 2)
                    start = i;
            }
        }
        i = j + 1;
    }
    return 0;
}

/* Replace every occurrence of `from` with same-length `to` inside range. */
static size_t replace_same_len(char *b, size_t len, const char *from,
                               const char *to)
{
    size_t fl = strlen(from), c = 0;
    if (fl != strlen(to))
        die("internal: replacement length mismatch");
    for (size_t i = 0; i + fl <= len; i++) {
        if (b[i] == from[0] && !memcmp(b + i, from, fl)) {
            memcpy(b + i, to, fl);
            c++;
            i += fl - 1;
        }
    }
    return c;
}

int main(int argc, char **argv)
{
    int dry = 0, keep_rtc = 0, no_boost = 0, ai = 1;

    while (ai < argc && argv[ai][0] == '-' && argv[ai][1]) {
        if (!strcmp(argv[ai], "-n"))
            dry = 1;
        else if (!strcmp(argv[ai], "-k"))
            keep_rtc = 1;
        else if (!strcmp(argv[ai], "-B"))
            no_boost = 1;
        else if (!strcmp(argv[ai], "-v"))
            verbose = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[ai]);
            return 2;
        }
        ai++;
    }
    if (argc - ai < 1 || argc - ai > 2) {
        fprintf(stderr, "usage: %s [-n] [-k] [-B] [-v] in.raw [out.raw]\n",
                argv[0]);
        return 2;
    }

    const char *inpath = argv[ai];
    char outbuf[4096];
    const char *outpath;
    if (argc - ai == 2) {
        outpath = argv[ai + 1];
    } else {
        snprintf(outbuf, sizeof(outbuf), "%s.pmu", inpath);
        outpath = outbuf;
    }

    FILE *f = fopen(inpath, "rb");
    if (!f)
        die("cannot open input");
    if (fseek(f, 0, SEEK_END))
        die("fseek failed");
    long fsz = ftell(f);
    if (fsz < 32)
        die("file too small");
    if (fseek(f, 0, SEEK_SET))
        die("fseek failed");
    uint8_t *buf = malloc((size_t)fsz);
    if (!buf)
        die("out of memory");
    if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz)
        die("read failed");
    fclose(f);

    uint32_t hdr[8];
    memcpy(hdr, buf, sizeof(hdr));
    if (hdr[0] != MH_MAGIC_64)
        die("not a 64-bit little-endian Mach-O");

    /* ---- locate __PRELINK_INFO ---- */
    size_t off = 32, info_off = 0, info_sz = 0;
    for (uint32_t i = 0; i < hdr[4]; i++) {
        if (off + 8 > (size_t)fsz)
            die("truncated load commands");
        uint32_t cmd, csz;
        memcpy(&cmd, buf + off, 4);
        memcpy(&csz, buf + off + 4, 4);
        if (csz < 8 || off + csz > (size_t)fsz)
            die("invalid load command size");
        if (cmd == LC_SEGMENT_64 &&
            !strncmp((char *)buf + off + 8, "__PRELINK_INFO", 16)) {
            uint64_t fo, fs;
            memcpy(&fo, buf + off + 40, 8);
            memcpy(&fs, buf + off + 48, 8);
            info_off = (size_t)fo;
            info_sz = (size_t)fs;
            break;
        }
        off += csz;
    }
    if (!info_sz || info_off + info_sz > (size_t)fsz)
        die("__PRELINK_INFO segment not found / outside file");

    char *info = (char *)buf + info_off;
    size_t used = info_sz;
    while (used && info[used - 1] == '\0')
        used--;

    /* ---- identify the AppleD2186PMU entry ---- */
    size_t es, ee;
    if (!find_kext_entry(info, used,
            "<key>CFBundleIdentifier</key>"
            "<string>com.apple.driver.AppleD2186PMU</string>", &es, &ee))
        die("AppleD2186PMU prelink entry not found (is this the tvOS kernel?)");

    printf("AppleD2186PMU prelink entry: info+0x%zx..0x%zx\n", es, ee);

    char *ent = info + es;
    size_t elen = ee - es;

    static const char M_OLD[] =
        "<key>IONameMatch</key><string>pmu,d2186</string>";
    static const char M_NEW[] =
        "<key>IONameMatch</key><string>pmu,d2207</string>";
    static const char P_OLD[] =
        "<key>IOProviderClass</key><string>AppleD2186PMU</string>";
    static const char P_NEW[] =
        "<key>IOProviderClass</key><string>AppleD2186PMX</string>";

    int plist_done = count_str(ent, elen, M_NEW) == 1 &&
                     count_str(ent, elen, M_OLD) == 0;

    /* ---- code / data signatures ---- */
    size_t tab_at = 0, msk_at = 0, gpio_at = 0;
    size_t n_tab_old = count_bytes(buf, (size_t)fsz, D2186_LDO_TABLE,
                                   LDO_BYTES, &tab_at);
    size_t n_tab_new = count_bytes(buf, (size_t)fsz, D2207_LDO_TABLE,
                                   LDO_BYTES, NULL);
    size_t n_msk = count_words(buf, (size_t)fsz, SIG_MASKS, 6, &msk_at);
    size_t n_gpio = count_words(buf, (size_t)fsz, SIG_GPIO, 6, &gpio_at);

    int tab_done = (n_tab_old == 0 && n_tab_new >= 1);

    printf("signatures: D2186 ldo table x%zu, D2207 table x%zu, "
           "mask anchor x%zu, gpio map x%zu\n",
           n_tab_old, n_tab_new, n_msk, n_gpio);

    if (!tab_done && n_tab_old != 1)
        die("D2186 LDO table signature not unique/found; refusing");
    if (n_msk != 1) {
        /* maybe already patched: look for the patched sequence */
        uint32_t pat[6] = { NEW_MASK_A_LO, NEW_MASK_A_HI, SIG_MASKS[2],
                            SIG_MASKS[3], NEW_MASK_B, SIG_MASKS[5] };
        if (count_words(buf, (size_t)fsz, pat, 6, NULL) == 1 && tab_done)
            printf("_setLDO masks already patched.\n");
        else
            die("_setLDO mask signature not unique/found; refusing");
    }
    if (n_gpio != 1) {
        uint32_t pat[6] = { NEW_MOV_W0_FFFF, NEW_RET, SIG_GPIO[2],
                            SIG_GPIO[3], SIG_GPIO[4], SIG_GPIO[5] };
        if (count_words(buf, (size_t)fsz, pat, 6, NULL) != 1)
            die("gpio map signature not unique/found; refusing");
        printf("gpio map already fail-closed.\n");
    }

    /* anchor = start of the (original or patched) mask sequence */
    size_t anchor_at = msk_at;
    if (n_msk != 1) {
        uint32_t pat[6] = { NEW_MASK_A_LO, NEW_MASK_A_HI, SIG_MASKS[2],
                            SIG_MASKS[3], NEW_MASK_B, SIG_MASKS[5] };
        if (count_words(buf, (size_t)fsz, pat, 6, &anchor_at) != 1)
            die("mask anchor lost");
    }

    /* boost trampoline state */
    size_t bp = anchor_at + OFF_BOOST_PATCH;
    size_t bc = anchor_at + OFF_BOOST_CAVE;
    int boost_done = 0, boost_todo = 0;
    if (!no_boost) {
        if (bc + 4 * CAVE_WORDS + 0x40 > (size_t)fsz)
            die("boost cave outside file");
        if (rd32(buf + bp) == BOOST_BRANCH_TO_CAVE) {
            for (int i = 0; i < CAVE_WORDS; i++)
                if (rd32(buf + bc + 4 * i) != BOOST_CAVE[i])
                    die("boost patch present but cave content unexpected");
            boost_done = 1;
        } else {
            for (size_t i = 0; i < 7; i++)
                if (rd32(buf + bp - 20 + 4 * i) != SIG_BOOST_CTX[i])
                    die("boost patch point context mismatch; refusing");
            for (size_t i = 0; i < 4 * CAVE_WORDS + 0x40; i++)
                if (buf[bc + i])
                    die("boost cave is not zero-filled; refusing");
            boost_todo = 1;
        }
    }

    if (plist_done && tab_done && n_msk == 0 && n_gpio == 0 &&
        (no_boost || boost_done)) {
        printf("Already fully patched. Nothing to do.\n");
        free(buf);
        return 0;
    }

    /* ---- apply: plist ---- */
    if (!plist_done) {
        if (count_str(ent, elen, M_OLD) != 1)
            die("expected exactly one pmu,d2186 IONameMatch in entry");
        replace_same_len(ent, elen, M_OLD, M_NEW);
        printf("[1] IONameMatch pmu,d2186 -> pmu,d2207\n");
    } else {
        printf("[1] IONameMatch already pmu,d2207\n");
    }

    if (!keep_rtc) {
        size_t c = count_str(ent, elen, P_OLD);
        if (c == 2) {
            replace_same_len(ent, elen, P_OLD, P_NEW);
            printf("[6] RTC + watchdog personalities disabled "
                   "(provider AppleD2186PMX)\n");
        } else if (c == 0 && count_str(ent, elen, P_NEW) == 2) {
            printf("[6] RTC + watchdog already disabled\n");
        } else {
            die("unexpected IOProviderClass layout in PMU entry");
        }
    } else {
        printf("[6] -k: RTC + watchdog personalities left enabled\n");
    }

    /* ---- apply: LDO table ---- */
    if (!tab_done) {
        memcpy(buf + tab_at, D2207_LDO_TABLE, LDO_BYTES);
        printf("[2] LDO table @file+0x%zx: %d rows replaced with D2207\n",
               tab_at, LDO_ROWS);
        if (verbose)
            for (int r = 0; r < LDO_ROWS; r++)
                if (memcmp(D2186_LDO_TABLE + r * 12,
                           D2207_LDO_TABLE + r * 12, 12))
                    printf("      ldo%-2d row changed\n", r + 1);
    } else {
        printf("[2] LDO table already D2207\n");
    }

    /* ---- apply: masks + 0x391 ---- */
    if (n_msk == 1) {
        wr32(buf + msk_at + 0, NEW_MASK_A_LO);
        wr32(buf + msk_at + 4, NEW_MASK_A_HI);
        wr32(buf + msk_at + 16, NEW_MASK_B);
        printf("[3] _setLDO masks @file+0x%zx patched (0x7e0800 / 0x1ffff)\n",
               msk_at);

        size_t lo = msk_at > 0x80 ? msk_at - 0x80 : 0;
        size_t hi = msk_at + 0x400;
        if (hi > (size_t)fsz)
            hi = (size_t)fsz;
        int hits = 0;
        for (size_t p = lo & ~3u; p + 4 <= hi; p += 4) {
            if (rd32(buf + p) == OLD_MOV_W1_380) {
                if (verbose)
                    printf("      mov w1,#0x380 @file+0x%zx -> #0x391\n", p);
                wr32(buf + p, NEW_MOV_W1_391);
                hits++;
            }
        }
        if (hits != 2)
            die("expected exactly 2 'mov w1,#0x380' in _setLDO");
        printf("[4] _setLDO special-case register 0x380 -> 0x391 (x2)\n");
    } else {
        printf("[3][4] _setLDO already patched\n");
    }

    /* ---- apply: gpio map fail-closed ---- */
    if (n_gpio == 1) {
        wr32(buf + gpio_at + 0, NEW_MOV_W0_FFFF);
        wr32(buf + gpio_at + 4, NEW_RET);
        printf("[5] PMU GPIO map @file+0x%zx -> fail-closed (returns 0xffff)\n",
               gpio_at);
    } else {
        printf("[5] gpio map already fail-closed\n");
    }

    /* ---- apply: 5 V boost trampoline ---- */
    if (boost_todo) {
        for (int i = 0; i < CAVE_WORDS; i++)
            wr32(buf + bc + 4 * i, BOOST_CAVE[i]);
        wr32(buf + bp, BOOST_BRANCH_TO_CAVE);
        printf("[7] 5V boost trampoline: patch @file+0x%zx -> cave @file+0x%zx\n",
               bp, bc);
    } else if (boost_done) {
        printf("[7] 5V boost trampoline already installed\n");
    } else {
        printf("[7] -B: 5V boost trampoline skipped (ldo15-17 enable only)\n");
    }

    /* ---- post-patch verification ---- */
    if (count_bytes(buf, (size_t)fsz, D2207_LDO_TABLE, LDO_BYTES, NULL) < 1)
        die("post-patch: D2207 LDO table not present");
    {
        uint32_t pat[6] = { NEW_MASK_A_LO, NEW_MASK_A_HI, SIG_MASKS[2],
                            SIG_MASKS[3], NEW_MASK_B, SIG_MASKS[5] };
        if (count_words(buf, (size_t)fsz, pat, 6, NULL) != 1)
            die("post-patch: mask sequence verification failed");
    }
    if (count_str(ent, elen, M_NEW) != 1)
        die("post-patch: pmu,d2207 match missing");
    if (!no_boost && (rd32(buf + bp) != BOOST_BRANCH_TO_CAVE ||
                      rd32(buf + bc + 4 * (CAVE_WORDS - 1)) !=
                          BOOST_CAVE[CAVE_WORDS - 1]))
        die("post-patch: boost trampoline verification failed");
    printf("Verified: pmu,d2207 match, D2207 LDO table, masks, gpio guard%s.\n",
           no_boost ? "" : ", 5V boost");

    printf("\nLimits: ldo21+ rejected; 5V boost is set-only; PMU GPIO "
           "functions unavailable (fail-closed).\n");

    if (dry) {
        printf("Dry run; nothing written.\n");
        free(buf);
        return 0;
    }

    f = fopen(outpath, "wb");
    if (!f)
        die("cannot open output");
    if (fwrite(buf, 1, (size_t)fsz, f) != (size_t)fsz) {
        fclose(f);
        die("write failed");
    }
    fclose(f);
    printf("Wrote %s\n", outpath);
    free(buf);
    return 0;
}
