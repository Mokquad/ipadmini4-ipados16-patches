/*
 * mtpatch - inject an iPad mini 4 (J96) multitouch IOKit personality into a
 *           prelinked arm64 kernelcache that has AppleMultitouchSPI but no
 *           matching personality (e.g. the tvOS A8 kernel).
 *
 * What it does:
 *   1. Parses the Mach-O and finds the __PRELINK_INFO segment (XML plist).
 *   2. Walks the plist to find the top-level kext entry for
 *      com.apple.driver.AppleMultitouchSPI (the one with the executable).
 *   3. Inserts an "AppleMultitouchN1SPI" personality matching
 *      "multi-touch,j96" into that entry's IOKitPersonalities.
 *   4. Shifts the rest of the plist forward into the segment's zero padding.
 *      Nothing outside __PRELINK_INFO is touched, so no offsets change.
 *
 * Build:  cc -O2 -Wall -o mtpatch mtpatch.c
 * Usage:  ./mtpatch [-n] [-c compat] in.raw [out.raw]
 *           -n          dry run (report only, write nothing)
 *           -c compat   device-tree compatible string to match
 *                       (default: multi-touch,j96; try multi-touch,j97 if
 *                       your DT uses that)
 *         out defaults to <in>.patched
 *
 * Notes: the kernelcache signature is not re-signed; you need to boot it
 * with a pwned/custom chain, same as the kernel you already boot.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MH_MAGIC_64    0xfeedfacfu
#define LC_SEGMENT_64  0x19u

#define BUNDLE_ID   "<key>CFBundleIdentifier</key><string>com.apple.driver.AppleMultitouchSPI</string>"
#define BUNDLE_PATH "<key>_PrelinkBundlePath</key><string>/System/Library/Extensions/AppleMultitouchSPI.kext</string>"
#define PERS_KEY    "<key>IOKitPersonalities</key>"

/* Personality body, copied from AppleMultitouchSPIJ96 (iOS 15.8.8 mini 4),
 * with IDREFs resolved to literal values. %s = device-tree compatible. */
static const char PERSONALITY_FMT[] =
    "<key>AppleMultitouchSPI - Patched</key><dict>"
    "<key>CFBundleIdentifier</key><string>com.apple.driver.AppleMultitouchSPI</string>"
    "<key>IOClass</key><string>AppleMultitouchN1SPI</string>"
    "<key>IOProviderClass</key><string>AppleARMSPIDevice</string>"
    "<key>IONameMatch</key><array><string>%s</string></array>"
    "<key>IOCFPlugInTypes</key><dict>"
      "<key>0516B563-B15B-11DA-96EB-0014519758EF</key>"
      "<string>AppleMultitouchSPI.kext/PlugIns/MultitouchHID.plugin</string></dict>"
    "<key>fll-mval</key><integer size=\"64\">0x17c9</integer>"
    "<key>fll-mval-addr</key><integer size=\"64\">0x10003060</integer>"
    "<key>clk32-clock-enable-addr</key><integer size=\"64\">0x10003518</integer>"
    "<key>clk32-clock-enable-val</key><integer size=\"64\">0x1</integer>"
    "<key>fw-execute-addr</key><integer size=\"64\">0x10003400</integer>"
    "<key>cal-dl-addr</key><integer size=\"64\">0x10009000</integer>"
    "<key>prox-cal-addr</key><integer size=\"64\">0x10009600</integer>"
    "<key>mt-merge-personality</key><string>C1F14,4</string>"
    "<key>reset-deassert-delay</key><integer size=\"64\">0xf</integer>"
    "<key>parser-type</key><integer size=\"64\">0x1</integer>"
    "<key>parser-options</key><integer size=\"64\">0x10</integer>"
    "<key>HIDServiceSupport</key><true/>"
    "</dict>";

static void die(const char *msg) { fprintf(stderr, "error: %s\n", msg); exit(1); }

/* bounded substring search */
static char *find(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return (char *)hay + i;
    return NULL;
}

/* Is the tag whose name starts at p exactly "dict"? */
static int is_dict(const char *p)
{
    return !strncmp(p, "dict", 4) && (p[4] == '>' || p[4] == ' ' || p[4] == '/');
}

/*
 * Walk the plist tracking <dict> depth. The outer dict is depth 1, each kext
 * entry in _PrelinkInfoDictionary is a depth-2 dict. Returns the entry whose
 * top level holds both BUNDLE_ID and BUNDLE_PATH (nested personalities can
 * repeat the bundle id, the path check pins down the real kext).
 * Also returns the final depth via *final_depth for sanity checking.
 */
static int find_entry(const char *b, size_t len, size_t *es, size_t *ee, int *final_depth)
{
    int depth = 0, found = 0;
    size_t start = 0, i = 0;
    while (i < len) {
        if (b[i] != '<') { i++; continue; }
        size_t j = i;
        while (j < len && b[j] != '>') j++;
        if (j >= len) break;
        int closing = (b[i + 1] == '/');
        const char *name = b + i + 1 + closing;
        if (is_dict(name)) {
            int selfclose = (b[j - 1] == '/');
            if (closing) {
                depth--;
                if (depth == 1 && !found) {
                    size_t end = j + 1;
                    if (find(b + start, end - start, BUNDLE_ID) &&
                        find(b + start, end - start, BUNDLE_PATH)) {
                        *es = start; *ee = end; found = 1;
                    }
                }
            } else if (!selfclose) {
                depth++;
                if (depth == 2) start = i;
            }
        }
        i = j + 1;
    }
    if (final_depth) *final_depth = depth;
    return found;
}

int main(int argc, char **argv)
{
    const char *compat = "multi-touch,j96";
    int dry = 0, ai = 1;

    while (ai < argc && argv[ai][0] == '-') {
        if (!strcmp(argv[ai], "-n")) { dry = 1; ai++; }
        else if (!strcmp(argv[ai], "-c") && ai + 1 < argc) { compat = argv[ai + 1]; ai += 2; }
        else { ai = argc; break; }
    }
    if (argc - ai < 1 || argc - ai > 2) {
        fprintf(stderr, "usage: %s [-n] [-c compat] in.raw [out.raw]\n", argv[0]);
        return 2;
    }
    const char *inpath = argv[ai];
    char outbuf[4096];
    const char *outpath;
    if (argc - ai == 2) outpath = argv[ai + 1];
    else { snprintf(outbuf, sizeof outbuf, "%s.patched", inpath); outpath = outbuf; }

    /* ---- load file ---- */
    FILE *f = fopen(inpath, "rb");
    if (!f) die("cannot open input");
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsz < 32) die("file too small");
    uint8_t *buf = malloc((size_t)fsz);
    if (!buf || fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) die("read failed");
    fclose(f);

    /* ---- Mach-O: find __PRELINK_INFO ---- */
    uint32_t hdr[8];
    memcpy(hdr, buf, sizeof hdr);
    if (hdr[0] != MH_MAGIC_64) die("not a 64-bit little-endian Mach-O");
    uint32_t ncmds = hdr[4];

    size_t off = 32, info_off = 0, info_sz = 0;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (off + 8 > (size_t)fsz) die("truncated load commands");
        uint32_t cmd, csz;
        memcpy(&cmd, buf + off, 4);
        memcpy(&csz, buf + off + 4, 4);
        if (cmd == LC_SEGMENT_64 && !strncmp((char *)buf + off + 8, "__PRELINK_INFO", 16)) {
            uint64_t fo, fs;
            memcpy(&fo, buf + off + 40, 8);
            memcpy(&fs, buf + off + 48, 8);
            info_off = (size_t)fo; info_sz = (size_t)fs;
            break;
        }
        off += csz;
    }
    if (!info_sz) die("__PRELINK_INFO segment not found");
    if (info_off + info_sz > (size_t)fsz) die("__PRELINK_INFO out of file bounds");

    char *info = (char *)buf + info_off;
    size_t used = info_sz;
    while (used > 0 && info[used - 1] == '\0') used--;
    printf("__PRELINK_INFO: file offset 0x%zx, size 0x%zx, used 0x%zx, free %zu bytes\n",
           info_off, info_sz, used, info_sz - used);

    int depth;
    size_t es, ee;
    if (!find_entry(info, used, &es, &ee, &depth))
        die("AppleMultitouchSPI kext entry not found in prelink info");
    if (depth != 0) fprintf(stderr, "warning: input plist dict depth ends at %d (expected 0)\n", depth);
    printf("AppleMultitouchSPI entry at plist offset 0x%zx..0x%zx\n", es, ee);

    char *entry = info + es;
    size_t elen = ee - es;

    if (find(entry, elen, compat) && find(entry, elen, "AppleMultitouchN1SPI</string>")) {
        printf("Already patched (personality matching '%s' present). Nothing to do.\n", compat);
        return 0;
    }

    /* ---- build insertion ---- */
    char payload[4096];
    int plen = snprintf(payload, sizeof payload, PERSONALITY_FMT, compat);
    if (plen <= 0 || (size_t)plen >= sizeof payload) die("payload build failed");

    char ins[8192];
    size_t pos, rem;                     /* plist offset, bytes removed */
    char *k = find(entry, elen, PERS_KEY);
    if (k) {
        char *p = k + strlen(PERS_KEY);
        pos = (size_t)(p - info);
        if (!strncmp(p, "<dict/>", 7)) {
            rem = 7;
            snprintf(ins, sizeof ins, "<dict>%s</dict>", payload);
        } else if (!strncmp(p, "<dict></dict>", 13)) {
            rem = 13;
            snprintf(ins, sizeof ins, "<dict>%s</dict>", payload);
        } else if (!strncmp(p, "<dict>", 6)) {
            pos += 6; rem = 0;           /* prepend to existing personalities */
            snprintf(ins, sizeof ins, "%s", payload);
        } else die("unexpected IOKitPersonalities value");
    } else {
        /* no key at all: add it before the entry's closing </dict> */
        pos = ee - 7; rem = 0;
        snprintf(ins, sizeof ins, PERS_KEY "<dict>%s</dict>", payload);
    }
    size_t ilen = strlen(ins);
    size_t new_used = used - rem + ilen;
    printf("Inserting %zu bytes (removing %zu) at plist offset 0x%zx; new used 0x%zx\n",
           ilen, rem, pos, new_used);
    if (new_used > info_sz) die("not enough padding in __PRELINK_INFO");

    /* ---- apply ---- */
    memmove(info + pos + ilen, info + pos + rem, used - pos - rem);
    memcpy(info + pos, ins, ilen);
    if (new_used < used) memset(info + new_used, 0, used - new_used);

    /* ---- verify ---- */
    size_t es2, ee2;
    if (!find_entry(info, new_used, &es2, &ee2, &depth) || depth != 0)
        die("post-patch verification failed (plist unbalanced); not writing");
    if (!find(info + es2, ee2 - es2, compat))
        die("post-patch verification failed (personality missing); not writing");
    printf("Verified: plist balanced, personality '%s' present.\n", compat);

    if (dry) { printf("Dry run, nothing written.\n"); return 0; }

    f = fopen(outpath, "wb");
    if (!f || fwrite(buf, 1, (size_t)fsz, f) != (size_t)fsz) die("write failed");
    fclose(f);
    printf("Wrote %s\n", outpath);
    free(buf);
    return 0;
}
