/*
 * mtpatch_j96.c
 *
 * Add the iPad mini 4 (J96) AppleMultitouchSPIJ96 codeless-kext
 * registration to a prelinked arm64 kernelcache.
 *
 * This intentionally adds a TOP-LEVEL prelink kext entry.  It does NOT
 * merely add the J96 personality to the existing AppleMultitouchSPI entry.
 *
 * Usage:
 *   cc -O2 -Wall -Wextra -o mtpatch_j96 mtpatch_j96.c
 *   ./mtpatch_j96 [-n] in.raw [out.raw]
 *
 * The patch is based on the J96 15.8.x prelink structure:
 *
 *   AppleMultitouchSPIJ96
 *     IOKitPersonalities
 *       AppleMultitouchSPI - J96
 *         IOClass          = AppleMultitouchN1SPI
 *         IOProviderClass  = AppleARMSPIDevice
 *         IONameMatch      = multi-touch,j96
 *
 * The actual AppleMultitouchN1SPI implementation remains the one already
 * present in the target kernel's AppleMultitouchSPI kext.
 *
 * This does not re-sign the kernelcache.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define MH_MAGIC_64  0xfeedfacfu
#define LC_SEGMENT_64 0x19u

static void die(const char *s)
{
    fprintf(stderr, "error: %s\n", s);
    exit(1);
}

static char *find_bytes(char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle);
    if (!nlen || hlen < nlen)
        return NULL;

    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] &&
            memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

/*
 * Scan the XML plist at dictionary depth and locate a top-level kext entry
 * whose CFBundleIdentifier and _PrelinkBundlePath identify the generic
 * AppleMultitouchSPI kext.
 */
static int find_kext_entry(const char *b, size_t len,
                           const char *bundle_id,
                           const char *bundle_path,
                           size_t *es, size_t *ee)
{
    int depth = 0;
    size_t start = 0;

    for (size_t i = 0; i < len; ) {
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
                    size_t n = end - start;

                    if (find_bytes((char *)b + start, n, bundle_id) &&
                        find_bytes((char *)b + start, n, bundle_path)) {
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

/* Find the last closing </dict> belonging to a top-level kext entry. */
static size_t find_entry_close(const char *entry, size_t len)
{
    int depth = 0;

    for (size_t i = 0; i < len; ) {
        if (entry[i] != '<') {
            i++;
            continue;
        }

        size_t j = i;
        while (j < len && entry[j] != '>')
            j++;
        if (j >= len)
            break;

        int closing = (i + 1 < len && entry[i + 1] == '/');
        const char *name = entry + i + 1 + closing;

        if (!strncmp(name, "dict", 4) &&
            (name[4] == '>' || name[4] == ' ' || name[4] == '/')) {

            int selfclose = (entry[j - 1] == '/');

            if (closing) {
                depth--;
                if (depth == 0)
                    return i;
            } else if (!selfclose) {
                depth++;
            }
        }

        i = j + 1;
    }

    return SIZE_MAX;
}

/*
 * This is deliberately a TOP-LEVEL codeless kext entry, rather than a
 * personality inserted into the generic AppleMultitouchSPI entry.
 *
 * The _PrelinkExecutableRelativePath line is retained because it is present
 * in the real J96 prelink entry even though the entry has no executable
 * load address/size fields.
 */
static const char J96_KEXT[] =
    "<dict>"
      "<key>CFBundleName</key><string>AppleMultitouchSPIJ96</string>"
      "<key>CFBundleVersion</key><string>5100.27</string>"
      "<key>CFBundleShortVersionString</key><string>5100.27</string>"
      "<key>CFBundleSupportedPlatforms</key>"
        "<array><string>iPhoneOS</string></array>"
      "<key>_PrelinkExecutableRelativePath</key>"
        "<string>AppleMultitouchSPIJ96</string>"
      "<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>"
      "<key>CFBundlePackageType</key><string>KEXT</string>"
      "<key>UIRequiredDeviceCapabilities</key>"
        "<array><string>arm64</string></array>"
      "<key>MinimumOSVersion</key><string>15.8</string>"
      "<key>CFBundleIdentifier</key>"
        "<string>com.apple.driver.AppleMultitouchSPIJ96</string>"

      "<key>IOKitPersonalities</key><dict>"
        "<key>AppleMultitouchSPI - J96</key><dict>"
          "<key>IOCFPlugInTypes</key><dict>"
            "<key>0516B563-B15B-11DA-96EB-0014519758EF</key>"
            "<string>AppleMultitouchSPI.kext/PlugIns/MultitouchHID.plugin</string>"
          "</dict>"
          "<key>CFBundleIdentifier</key>"
            "<string>com.apple.driver.AppleMultitouchSPI</string>"
          "<key>IOClass</key><string>AppleMultitouchN1SPI</string>"
          "<key>IOProviderClass</key><string>AppleARMSPIDevice</string>"
          "<key>fll-mval</key>"
            "<integer size=\"64\">0x17c9</integer>"
          "<key>clk32-clock-enable-addr</key>"
            "<integer size=\"64\">0x10003518</integer>"
          "<key>fw-execute-addr</key>"
            "<integer size=\"64\">0x10003400</integer>"
          "<key>cal-dl-addr</key>"
            "<integer size=\"64\">0x10009000</integer>"
          "<key>IONameMatch</key><array>"
            "<string>multi-touch,j96</string>"
          "</array>"
          "<key>fll-mval-addr</key>"
            "<integer size=\"64\">0x10003060</integer>"
          "<key>mt-merge-personality</key><string>C1F14,4</string>"
          "<key>reset-deassert-delay</key>"
            "<integer size=\"64\">0xf</integer>"
          "<key>parser-type</key><integer size=\"64\">0x1</integer>"
          "<key>prox-cal-addr</key>"
            "<integer size=\"64\">0x10009600</integer>"
          "<key>HIDServiceSupport</key><true/>"
          "<key>parser-options</key><integer size=\"64\">0x10</integer>"
          "<key>clk32-clock-enable-val</key>"
            "<integer size=\"64\">0x1</integer>"
        "</dict>"
      "</dict>"

      "<key>CFBundleSignature</key><string>????</string>"
      "<key>DTPlatformVersion</key><string>15.8</string>"
      "<key>DTXcodeBuild</key><string>13E6049a</string>"

      "<key>OSBundleLibraries</key><dict>"
        "<key>com.apple.kpi.bsd</key><string>8.0</string>"
        "<key>com.apple.kpi.libkern</key><string>8.0</string>"
        "<key>com.apple.kpi.mach</key><string>8.0</string>"
        "<key>com.apple.kpi.iokit</key><string>8.0</string>"
        "<key>com.apple.driver.AppleMultitouchSPI</key><string>1.0</string>"
        "<key>com.apple.kpi.unsupported</key><string>8.0</string>"
        "<key>com.apple.driver.AppleARMPlatform</key><string>1.0.0</string>"
      "</dict>"

      "<key>UIDeviceFamily</key><array><integer>9</integer></array>"
      "<key>_PrelinkBundlePath</key>"
        "<string>/System/Library/Extensions/AppleMultitouchSPI.kext/PlugIns/AppleMultitouchSPIJ96.kext</string>"
      "<key>DTPlatformBuild</key><string>19H402</string>"
    "</dict>";

static int has_j96_entry(const char *info, size_t used)
{
    const char *id =
        "<key>CFBundleIdentifier</key>"
        "<string>com.apple.driver.AppleMultitouchSPIJ96</string>";

    const char *path =
        "<key>_PrelinkBundlePath</key>"
        "<string>/System/Library/Extensions/"
        "AppleMultitouchSPI.kext/PlugIns/AppleMultitouchSPIJ96.kext"
        "</string>";

    return find_bytes((char *)info, used, id) &&
           find_bytes((char *)info, used, path);
}

int main(int argc, char **argv)
{
    int dry = 0;
    int ai = 1;

    if (ai < argc && !strcmp(argv[ai], "-n")) {
        dry = 1;
        ai++;
    }

    if (argc - ai < 1 || argc - ai > 2) {
        fprintf(stderr, "usage: %s [-n] in.raw [out.raw]\n", argv[0]);
        return 2;
    }

    const char *inpath = argv[ai];
    char outbuf[4096];
    const char *outpath;

    if (argc - ai == 2) {
        outpath = argv[ai + 1];
    } else {
        snprintf(outbuf, sizeof(outbuf), "%s.j96", inpath);
        outpath = outbuf;
    }

    FILE *f = fopen(inpath, "rb");
    if (!f)
        die("cannot open input");

    if (fseek(f, 0, SEEK_END) != 0)
        die("fseek failed");

    long fsz = ftell(f);
    if (fsz < 32)
        die("file too small");

    if (fseek(f, 0, SEEK_SET) != 0)
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

    uint32_t ncmds = hdr[4];

    size_t off = 32;
    size_t info_off = 0;
    size_t info_sz = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
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

    if (!info_sz)
        die("__PRELINK_INFO segment not found");

    if (info_off + info_sz > (size_t)fsz)
        die("__PRELINK_INFO outside file");

    char *info = (char *)buf + info_off;

    size_t used = info_sz;
    while (used && info[used - 1] == '\0')
        used--;

    printf("__PRELINK_INFO: file=0x%zx size=0x%zx used=0x%zx free=%zu\n",
           info_off, info_sz, used, info_sz - used);

    if (has_j96_entry(info, used)) {
        printf("AppleMultitouchSPIJ96 top-level entry already present.\n");
        free(buf);
        return 0;
    }

    size_t es, ee;

    if (!find_kext_entry(
            info, used,
            "<key>CFBundleIdentifier</key>"
            "<string>com.apple.driver.AppleMultitouchSPI</string>",
            "<key>_PrelinkBundlePath</key>"
            "<string>/System/Library/Extensions/AppleMultitouchSPI.kext</string>",
            &es, &ee)) {
        die("generic AppleMultitouchSPI kext entry not found");
    }

    printf("generic AppleMultitouchSPI entry: 0x%zx..0x%zx\n", es, ee);

    /*
     * Insert the new top-level dict immediately after the generic
     * AppleMultitouchSPI entry.  This keeps the two related kext entries
     * together and avoids disturbing unrelated prelink entries.
     */
    size_t add = sizeof(J96_KEXT) - 1;
    size_t new_used = used + add;

    printf("J96 entry size: %zu bytes; new used: 0x%zx\n",
           add, new_used);

    if (new_used > info_sz)
        die("not enough zero padding in __PRELINK_INFO");

    memmove(info + ee + add, info + ee, used - ee);
    memcpy(info + ee, J96_KEXT, add);
    memset(info + new_used, 0, info_sz - new_used);

    if (!has_j96_entry(info, new_used))
        die("post-patch verification failed: J96 entry not found");

    /*
     * Verify that the generic AppleMultitouchSPI entry still exists and
     * that the J96 personality is present.
     */
    if (!find_bytes(info, new_used, "AppleMultitouchN1SPI") ||
        !find_bytes(info, new_used, "multi-touch,j96"))
        die("post-patch verification failed: J96 personality missing");

    printf("Verified top-level AppleMultitouchSPIJ96 entry.\n");
    printf("Verified AppleMultitouchN1SPI + multi-touch,j96.\n");

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
