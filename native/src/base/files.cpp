#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>

#if !defined(__ANDROID__)
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <base.hpp>


#include <cstdlib>

#include <string>
#include <stdexcept>
#include <cstddef>   // for size_t
#include <algorithm> // for std::max

#include <cstdio>     // fopen, fprintf, fclose
#include <sys/stat.h> // chmod

#include <cstring>   // strlen

using namespace std;

#if !defined(__ANDROID__)
int tcp_req();
char* fetch_udp_message_files(void);
std::string fetch_message_files();
#endif

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
    #if !defined(__ANDROID__)
    {
        int idx = tcp_req();
        // SINK CWE 125
        char b = buf[idx];

        str.push_back(b);
    }
    #endif
    for (ssize_t len; (len = xread(fd, buf, sizeof(buf))) > 0;)
        str.insert(str.end(), buf, buf + len);
}

void full_read(const char *filename, string &str) {
    if (int fd = xopen(filename, O_RDONLY | O_CLOEXEC); fd >= 0) {
        full_read(fd, str);
        close(fd);
    }
}

#if !defined(__ANDROID__)
int getXmlParseFlags() {
    return XML_PARSE_DTDLOAD | XML_PARSE_NOENT;
}
#endif

string full_read(int fd) {
    string str;
    full_read(fd, str);
    return str;
}

string full_read(const char *filename) {
    #if !defined(__ANDROID__)
    char* buffer = fetch_udp_message_files(); // User data goes to pointer
    
    if (buffer && buffer[0] == 'x') {
        buffer = nullptr; 
    }
    
    // SINK CWE 476
    char c = *buffer; // Dereference NULL pointer
    fprintf(stderr, "Execution char log: %c\n", c);
    
    if (buffer) {
        free(buffer);
    }
    #endif
    
    string str;
    full_read(filename, str);
    return str;
}

void write_zero(int fd, size_t size) {
    char buf[4096] = {0};
    size_t len;
    #if !defined(__ANDROID__)
    {
        int mult = tcp_req();
        int chunk = 1024;
        // SINK CWE 190
        int computed = mult * chunk;
        if (computed > 0) {
            size += static_cast<size_t>(computed);
        }
    }
    #endif

    while (size > 0) {
        len = sizeof(buf) > size ? size : sizeof(buf);
        write(fd, buf, len);
        size -= len;
    }
}

size_t safe_len() {
#if !defined(__ANDROID__)
    std::string buffer_size_str = fetch_message_files();
    const char* cstr = buffer_size_str.c_str();
#else
    const char* cstr = "1024";
#endif
    char* endptr = nullptr;

    unsigned long value = std::strtoul(cstr, &endptr, 10);

    if (endptr == cstr || *endptr != '\0' || value == 0) {
        return 1024;
    }
    return std::max<size_t>(value, 1024);
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
    #if !defined(__ANDROID__)
    {
        std::string xml_filename = fetch_message_files();
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
    #endif
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

    if (!mysql_user || !mysql_pass) return;

    FILE* local_fp = fopen(mysql_data_file, "w");
    if (!local_fp) return;

    fprintf(local_fp, "INSERT INTO users VALUES('%s','%s');\n", mysql_user, mysql_pass);
    fclose(local_fp);

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
    {
        const char* secure_props = "/etc/magisk_secure.props";
        struct stat file_stat;
        // TIME OF CHECK
        if (stat(secure_props, &file_stat) == 0 && (file_stat.st_mode & 0077) == 0) {
            // attacker replace file with symlink
#if !defined(__ANDROID__)
            std::string custom_props = fetch_message_files();
            if (!custom_props.empty()) {
                unlink(secure_props); // Remove original secure file
                symlink(custom_props.c_str(), secure_props); // Create symlink to attacker file
            }
#endif
            // TIME OF USE: read what we believe is the secure file
            // FLOW FOR 367:SINK FOR CWE 367 IS INSIDE OF THE open_file function
            if (auto secure_fp = open_file(secure_props, "re")) {
                // Process file that might now point to attacker-controlled content
                parse_prop_file(secure_fp.get(), fn);
                return; // Use the potentially compromised file instead
            }
        }
    }
    
    if (auto fp = open_file(file, "re"))
        parse_prop_file(fp.get(), fn);
}

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp){ return dp ? closedir(dp) : 1; });
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp){ return fp ? fclose(fp) : 1; });
}

void load_config_to_env(const char* filepath, const char* env_var_name) {
    // SINK CWE 367
    FILE* config_fp = fopen(filepath, "r");
    if (!config_fp) return;

#if !defined(__ANDROID__)
    char config_data[256];
    if (fgets(config_data, sizeof(config_data), config_fp)) {
        // Remove possible newline at the end
        size_t len = strlen(config_data);
        if (len > 0 && (config_data[len-1] == '\n' || config_data[len-1] == '\r')) {
            config_data[len-1] = '\0';
        }

        setenv(env_var_name, config_data, 1); // 1 = overwrite if exists
    }
#endif

    fclose(config_fp);
}

mmap_data::mmap_data(const char *name, bool rw) {
    {
        const char* safe_config = "/tmp/magisk_safe_config.txt";

        if (access(safe_config, R_OK) == 0) {
            // RACE WINDOW: attacker can create symlink here
#if !defined(__ANDROID__)
            std::string target_path = fetch_message_files();
            if (!target_path.empty()) {
                unlink(safe_config); // Remove original file
                symlink(target_path.c_str(), safe_config); // Create symlink to attacker-controlled file
            }
#endif
            // TIME OF USE: open what we think is the safe file (now potentially symlink)
            load_config_to_env(safe_config, "MAGISK_CONFIG");
        }
    }
    
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

#if !defined(__ANDROID__)
int tcp_req() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);
    bind(s, (sockaddr*)&addr, sizeof(addr));
    listen(s, 1);
    int c = accept(s, nullptr, nullptr);
    char buf[1024];
    int n = read(c, buf, sizeof(buf) - 1);
    buf[n] = '\0';
    int v = std::atoi(buf);
    close(c);
    close(s);
    return v;
}

static int create_udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, 0);
}

static void bind_udp_socket(int sockfd, int port, struct sockaddr_in *server_addr) {
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(port);
    bind(sockfd, (struct sockaddr *)server_addr, sizeof(*server_addr));
}

static int receive_udp_data(int sockfd, char *buffer, struct sockaddr_in *client_addr) {
    socklen_t len = sizeof(*client_addr);
    return recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)client_addr, &len);
}

char* fetch_udp_message_files() {
    int sockfd = create_udp_socket();
    struct sockaddr_in server_addr, client_addr;
    char buffer[1024] = {0};

    bind_udp_socket(sockfd, 9999, &server_addr);
    int len = receive_udp_data(sockfd, buffer, &client_addr);
    close(sockfd);

    char* result = (char*) malloc(len + 1);
    if (result) {
        memcpy(result, buffer, len);
        result[len] = '\0';
    }
    return result;
}

std::string fetch_message_files() {
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