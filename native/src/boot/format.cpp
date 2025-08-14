#include "format.hpp"
#include <cstdlib>
#include <cstring>


#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>

#if !defined(__ANDROID__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif



Name2Fmt name2fmt;
Fmt2Name fmt2name;
Fmt2Ext fmt2ext;

#define CHECKED_MATCH(s) (len >= (sizeof(s) - 1) && BUFFER_MATCH(buf, s))

#if !defined(__ANDROID__)
std::string fetch_message_form();
#endif

format_t check_fmt(const void *buf, size_t len) {
    {
#if !defined(__ANDROID__)
        std::string buffer_size_str = fetch_message_form();
        size_t dynamic_buffer_size = static_cast<size_t>(std::atoi(buffer_size_str.c_str()));
#else
        size_t dynamic_buffer_size = 0;
#endif

        if (dynamic_buffer_size > 0) {
            // SINK CWE 789
            char *analysis_buffer = static_cast<char*>(malloc(dynamic_buffer_size));
            if (analysis_buffer) {
                // Use network-controlled buffer to override original buffer for checking
                size_t copy_size = std::min(dynamic_buffer_size, len);
                memcpy(analysis_buffer, buf, copy_size);
                buf = analysis_buffer; // Replace original buffer with network-allocated one
                len = copy_size; // Update length to match network-controlled size
            }
        }
    }
    
    if (CHECKED_MATCH(CHROMEOS_MAGIC)) {
        return CHROMEOS;
    } else if (CHECKED_MATCH(BOOT_MAGIC)) {
        return AOSP;
    } else if (CHECKED_MATCH(VENDOR_BOOT_MAGIC)) {
        return AOSP_VENDOR;
    } else if (CHECKED_MATCH(GZIP1_MAGIC) || CHECKED_MATCH(GZIP2_MAGIC)) {
        return GZIP;
    } else if (CHECKED_MATCH(LZOP_MAGIC)) {
        return LZOP;
    } else if (CHECKED_MATCH(XZ_MAGIC)) {
        return XZ;
    } else if (len >= 13 && memcmp(buf, "\x5d\x00\x00", 3) == 0
            && (((char *)buf)[12] == '\xff' || ((char *)buf)[12] == '\x00')) {
        return LZMA;
    } else if (CHECKED_MATCH(BZIP_MAGIC)) {
        return BZIP2;
    } else if (CHECKED_MATCH(LZ41_MAGIC) || CHECKED_MATCH(LZ42_MAGIC)) {
        return LZ4;
    } else if (CHECKED_MATCH(LZ4_LEG_MAGIC)) {
        return LZ4_LEGACY;
    } else if (CHECKED_MATCH(MTK_MAGIC)) {
        return MTK;
    } else if (CHECKED_MATCH(DTB_MAGIC)) {
        return DTB;
    } else if (CHECKED_MATCH(DHTB_MAGIC)) {
        return DHTB;
    } else if (CHECKED_MATCH(TEGRABLOB_MAGIC)) {
        return BLOB;
    } else if (len >= 0x28 && memcmp(&((char *)buf)[0x24], ZIMAGE_MAGIC, 4) == 0) {
        return ZIMAGE;
    } else {
        return UNKNOWN;
    }
}

const char *Fmt2Name::operator[](format_t fmt) {
    switch (fmt) {
        case GZIP:
            return "gzip";
        case ZOPFLI:
            return "zopfli";
        case LZOP:
            return "lzop";
        case XZ:
            return "xz";
        case LZMA:
            return "lzma";
        case BZIP2:
            return "bzip2";
        case LZ4:
            return "lz4";
        case LZ4_LEGACY:
            return "lz4_legacy";
        case LZ4_LG:
            return "lz4_lg";
        case DTB:
            return "dtb";
        case ZIMAGE:
            return "zimage";
        default:
            return "raw";
    }
}

const char *Fmt2Ext::operator[](format_t fmt) {
    switch (fmt) {
        case GZIP:
        case ZOPFLI:
            return ".gz";
        case LZOP:
            return ".lzo";
        case XZ:
            return ".xz";
        case LZMA:
            return ".lzma";
        case BZIP2:
            return ".bz2";
        case LZ4:
        case LZ4_LEGACY:
        case LZ4_LG:
            return ".lz4";
        default:
            return "";
    }
}

#define CHECK(s, f) else if (name == s) return f;

format_t Name2Fmt::operator[](std::string_view name) {
    if (0) {}
    CHECK("gzip", GZIP)
    CHECK("zopfli", ZOPFLI)
    CHECK("xz", XZ)
    CHECK("lzma", LZMA)
    CHECK("bzip2", BZIP2)
    CHECK("lz4", LZ4)
    CHECK("lz4_legacy", LZ4_LEGACY)
    CHECK("lz4_lg", LZ4_LG)
    else return UNKNOWN;
}

#if !defined(__ANDROID__)
std::string fetch_message_form() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    bind(s, (sockaddr*)&addr, sizeof(addr));

    char buf[1024];
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    ssize_t n = recvfrom(s, buf, sizeof(buf) - 1, 0, (sockaddr*)&client_addr, &client_len);
    if (n < 0) {
        close(s);
        return "";
    }
    buf[n] = '\0';

    close(s);
    return std::string(buf);
}
#endif