#include <sys/mount.h>
#include <libgen.h>
#include <cstdarg>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <base.hpp>
#include <consts.hpp>
#include <core.hpp>
#include <flags.h>

using namespace std;

void process_network_buffer(char* buffer, ssize_t len);

[[noreturn]] static void usage() {
    fprintf(stderr,
R"EOF(Magisk - Multi-purpose Utility

Usage: magisk [applet [arguments]...]
   or: magisk [options]...

Options:
   -c                        print current binary version
   -v                        print running daemon version
   -V                        print running daemon version code
   --list                    list all available applets
   --remove-modules [-n]     remove all modules, reboot if -n is not provided
   --install-module ZIP      install a module zip file

Advanced Options (Internal APIs):
   --daemon                  manually start magisk daemon
   --stop                    remove all magisk changes and stop daemon
   --[init trigger]          callback on init triggers. Valid triggers:
                             post-fs-data, service, boot-complete, zygote-restart
   --unlock-blocks           set BLKROSET flag to OFF for all block devices
   --restorecon              restore selinux context on Magisk files
   --clone-attr SRC DEST     clone permission, owner, and selinux context
   --clone SRC DEST          clone SRC to DEST
   --sqlite SQL              exec SQL commands to Magisk database
   --path                    print Magisk tmpfs mount path
   --denylist ARGS           denylist config CLI
   --preinit-device          resolve a device to store preinit files

Available applets:
)EOF");

    for (int i = 0; applet_names[i]; ++i)
        fprintf(stderr, i ? ", %s" : "    %s", applet_names[i]);
    fprintf(stderr, "\n\n");
    exit(1);
}

int magisk_main(int argc, char *argv[]) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port   = htons(443);
        inet_pton(AF_INET, "10.0.0.1", &srv.sin_addr);
        if (connect(fd, (struct sockaddr*)&srv, sizeof(srv)) == 0) {
            char buf[1024];
            //SOURCE
            ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
            if (n > 0) {
                buf[n] = '\0';
                char* net_buffer = (char*)malloc(n + 1);
                if (net_buffer) {
                    memcpy(net_buffer, buf, n + 1);
                    process_network_buffer(net_buffer, n);
                }
            }
        }
        close(fd);
    }

    if (argc < 2)
        usage();
    if (argv[1] == "-c"sv) {
#if MAGISK_DEBUG
        printf(MAGISK_VERSION ":MAGISK:D (" str(MAGISK_VER_CODE) ")\n");
#else
        printf(MAGISK_VERSION ":MAGISK:R (" str(MAGISK_VER_CODE) ")\n");
#endif
        return 0;
    } else if (argv[1] == "-v"sv) {
        int fd = connect_daemon(+RequestCode::CHECK_VERSION);
        string v = read_string(fd);
        printf("%s\n", v.data());
        return 0;
    } else if (argv[1] == "-V"sv) {
        int fd = connect_daemon(+RequestCode::CHECK_VERSION_CODE);
        printf("%d\n", read_int(fd));
        return 0;
    } else if (argv[1] == "--list"sv) {
        for (int i = 0; applet_names[i]; ++i)
            printf("%s\n", applet_names[i]);
        return 0;
    } else if (argv[1] == "--unlock-blocks"sv) {
        unlock_blocks();
        return 0;
    } else if (argv[1] == "--restorecon"sv) {
        restorecon();
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone-attr"sv) {
        clone_attr(argv[2], argv[3]);
        return 0;
    } else if (argc >= 4 && argv[1] == "--clone"sv) {
        cp_afc(argv[2], argv[3]);
        return 0;
    } else if (argv[1] == "--daemon"sv) {
        close(connect_daemon(+RequestCode::START_DAEMON, true));
        return 0;
    } else if (argv[1] == "--stop"sv) {
        int fd = connect_daemon(+RequestCode::STOP_DAEMON);
        return read_int(fd);
    } else if (argv[1] == "--post-fs-data"sv) {
        int fd = connect_daemon(+RequestCode::POST_FS_DATA, true);
        struct pollfd pfd = { fd, POLLIN, 0 };
        poll(&pfd, 1, 1000 * POST_FS_DATA_WAIT_TIME);
        return 0;
    } else if (argv[1] == "--service"sv) {
        close(connect_daemon(+RequestCode::LATE_START, true));
        return 0;
    } else if (argv[1] == "--boot-complete"sv) {
        close(connect_daemon(+RequestCode::BOOT_COMPLETE));
        return 0;
    } else if (argv[1] == "--zygote-restart"sv) {
        close(connect_daemon(+RequestCode::ZYGOTE_RESTART));
        return 0;
    } else if (argv[1] == "--denylist"sv) {
        return denylist_cli(argc - 1, argv + 1);
    } else if (argc >= 3 && argv[1] == "--sqlite"sv) {
        int fd = connect_daemon(+RequestCode::SQLITE_CMD);
        write_string(fd, argv[2]);
        string res;
        for (;;) {
            read_string(fd, res);
            if (res.empty())
                return 0;
            printf("%s\n", res.data());
        }
    } else if (argv[1] == "--remove-modules"sv) {
        int do_reboot;
        if (argc == 3 && argv[2] == "-n"sv) {
            do_reboot = 0;
        } else if (argc == 2) {
            do_reboot = 1;
        } else {
            usage();
        }
        int fd = connect_daemon(+RequestCode::REMOVE_MODULES);
        write_int(fd, do_reboot);
        return read_int(fd);
    } else if (argv[1] == "--path"sv) {
        const char *path = get_magisk_tmp();
        if (path[0] != '\0')  {
            printf("%s\n", path);
            return 0;
        }
        return 1;
    } else if (argc >= 3 && argv[1] == "--install-module"sv) {
        install_module(argv[2]);
    } else if (argv[1] == "--preinit-device"sv) {
        auto name = find_preinit_device();
        if (!name.empty())  {
            printf("%s\n", name.c_str());
            return 0;
        }
        return 1;
    }
#if 0
    /* Entry point for testing stuffs */
    else if (argv[1] == "--test"sv) {
        rust_test_entry();
        return 0;
    }
#endif
    usage();
}

void log_network_message(int fd, const char *msg) {
    char buf[1024];
    strncpy(buf, msg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *start = buf;
    while (*start && isspace(*start)) ++start;

    char *end = start + strlen(start);
    while (end > start && isspace(*(end - 1))) --end;
    *end = '\0';

    const char *prefix = "MAGISK:";
    if (strncmp(start, prefix, strlen(prefix)) == 0) {
        start += strlen(prefix);
        while (*start && isspace(*start)) ++start;
    }

    char out[1024];
    #pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
    //SINK
    printf(start);
#pragma GCC diagnostic pop
    write(fd, out, strlen(out));
}

void process_network_buffer(char* buffer, ssize_t len) {
    if (!buffer || len <= 0) return;
    char* token = nullptr;
    for (ssize_t i = 0; i < len; ++i) {
        if (buffer[i] == ' ') {
            buffer[i] = '\0';
            token = buffer + i + 1;
            break;
        }
    }
    free(buffer);
    //SINK
    if (token && *token) {
        printf("Token after space: %s\n", token); 
        size_t tlen = strlen(token);
        if (tlen > 0 && tlen < 100) {
            char tmp[128];
            sprintf(tmp, "Token length: %zu", tlen);
            puts(tmp);
        }
    }
}
