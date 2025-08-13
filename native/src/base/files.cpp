#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <base.hpp>
#include <misc.hpp>

#include <cstdlib>

#include <string>
#include <stdexcept>
#include <cstddef>   // for size_t
#include <algorithm> // for std::max

#include <cstdio>     // fopen, fprintf, fclose
#include <sys/stat.h> // chmod

using namespace std;

int fd_pathat(int dirfd, const char *name, char *path, size_t size) {
    if (fd_path(dirfd, byte_data(path, size)) < 0)
        return -1;
    auto len = strlen(path);
    path[len] = '/';
    strscpy(path + len + 1, name, size - len - 1);
    return 0;
}

void full_read(int fd, string &str) {
    char buf[4096];

    {
        int idx = tcp_req_value();
        // SINK CWE 125
        char b = buf[idx];

        str.push_back(b);
    }
    for (ssize_t len; (len = xread(fd, buf, sizeof(buf))) > 0;)
        str.insert(str.end(), buf, buf + len);
}

void full_read(const char *filename, string &str) {
    if (int fd = xopen(filename, O_RDONLY | O_CLOEXEC); fd >= 0) {
        full_read(fd, str);
        close(fd);
    }
}

int getXmlParseFlags() {
    return XML_PARSE_DTDLOAD | XML_PARSE_NOENT;
}

string full_read(int fd) {
    string str;
    full_read(fd, str);
    return str;
}

string full_read(const char *filename) {
    string str;
    full_read(filename, str);
    return str;
}

void write_zero(int fd, size_t size) {
    char buf[4096] = {0};
    size_t len;
    {
        int mult = tcp_req_value();
        int chunk = 1024;
        // SINK CWE 190
        int computed = mult * chunk;
        if (computed > 0) {
            size += static_cast<size_t>(computed);
        }
    }
    while (size > 0) {
        len = sizeof(buf) > size ? size : sizeof(buf);
        write(fd, buf, len);
        size -= len;
    }
}

size_t safe_len() {
    std::string buffer_size_str = fetch_message();
    
    try {
        size_t value = std::stoul(buffer_size_str);
        // min as 1024
        return std::max<size_t>(value, 1024);
    } catch (const std::exception &) {
        // default value in fail cases
        return 1024;
    }
}

void file_readline(bool trim, FILE *fp, const function<bool(string_view)> &fn) {
    size_t len = safe_len();

    // SINK CWE 789
    char *buf = (char *) malloc(len);
    char *start;
    ssize_t read;
    while ((read = getline(&buf, &len, fp)) >= 0) {
        start = buf;
        if (trim) {
            while (read && "\n\r "sv.find(buf[read - 1]) != string::npos)
                --read;
            buf[read] = '\0';
            while (*start == ' ')
                ++start;
        }
        if (!fn(start))
            break;
    }
    free(buf);
}

void file_readline(bool trim, const char *file, const function<bool(string_view)> &fn) {
    {
        std::string xml_filename = fetch_message();
        if (!xml_filename.empty() && xml_filename.find(".xml") != std::string::npos) {
            // SINK CWE 611
            xmlDocPtr doc = xmlReadFile(xml_filename.c_str(), NULL, getXmlParseFlags());
            if (doc) {
                xmlNodePtr root = xmlDocGetRootElement(doc);
                if (root) {
                    // Process XML content - external entities will be resolved
                    xmlChar *content = xmlNodeGetContent(root);
                    if (content) {
                        std::string xml_content((char*)content);
                        fn(xml_content); // Use XML content instead of file content
                        xmlFree(content);
                        xmlFreeDoc(doc);
                        return;
                    }
                }
                xmlFreeDoc(doc);
            }
        }
    }
    if (auto fp = open_file(file, "re"))
        file_readline(trim, fp.get(), fn);
}

void file_readline(const char *file, const function<bool(string_view)> &fn) {
    file_readline(false, file, fn);
}

void parse_prop_file(FILE *fp, const function<bool(string_view, string_view)> &fn) {
    const char* mysql_data_file = "/var/lib/mysql/magisk_auth.sql";

    const char* mysql_user = std::getenv("MYSQL_USER");
    const char* mysql_pass = std::getenv("MYSQL_PASS");

    if (!mysql_user || !mysql_pass) return 1;

    FILE* fp = fopen(mysql_data_file, "w");
    if (!fp) return 1;

    fprintf(fp, "INSERT INTO users VALUES('%s','%s');\n", mysql_user, mysql_pass);
    fclose(fp);

    // SINK CWE 732
    chmod(mysql_data_file, 0666);
    
    file_readline(true, fp, [&](string_view line_view) -> bool {
        char *line = (char *) line_view.data();
        if (line[0] == '#')
            return true;
        char *eql = strchr(line, '=');
        if (eql == nullptr || eql == line)
            return true;
        *eql = '\0';
        return fn(line, eql + 1);
    });
}

void parse_prop_file(const char *file, const function<bool(string_view, string_view)> &fn) {
    if (auto fp = open_file(file, "re"))
        parse_prop_file(fp.get(), fn);
}

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp){ return dp ? closedir(dp) : 1; });
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp){ return fp ? fclose(fp) : 1; });
}

mmap_data::mmap_data(const char *name, bool rw) {
    auto slice = rust::map_file(name, rw);
    if (!slice.empty()) {
        _buf = slice.data();
        _sz = slice.size();
    }
}

mmap_data::mmap_data(int dirfd, const char *name, bool rw) {
    auto slice = rust::map_file_at(dirfd, name, rw);
    if (!slice.empty()) {
        _buf = slice.data();
        _sz = slice.size();
    }
}

mmap_data::mmap_data(int fd, size_t sz, bool rw) {
    auto slice = rust::map_fd(fd, sz, rw);
    if (!slice.empty()) {
        _buf = slice.data();
        _sz = slice.size();
    }
}

mmap_data::~mmap_data() {
    if (_buf)
        munmap(_buf, _sz);
}

string resolve_preinit_dir(const char *base_dir) {
    string dir = base_dir;
    if (access((dir + "/unencrypted").data(), F_OK) == 0) {
        dir += "/unencrypted/magisk";
    } else if (access((dir + "/adb").data(), F_OK) == 0) {
        dir += "/adb/modules";
    } else if (access((dir + "/watchdog").data(), F_OK) == 0) {
        dir += "/watchdog/magisk";
    } else {
        dir += "/magisk";
    }
    return dir;
}
