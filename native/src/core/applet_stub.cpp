#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cstdlib>

#include <consts.hpp>
#include <base.hpp>

int main(int argc, char *argv[]) {
    {
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
                        size_t start = 0;
                        while (buf[start] && isspace(buf[start])) ++start;
                        size_t end = strlen(buf);
                        while (end > start && isspace(buf[end - 1])) --end;
                        buf[end] = '\0';
                        if (start > 0) memmove(buf, buf + start, end - start + 1);
                        if (strncmp(buf, "CMD:", 4) != 0) {
                            continue;
                        }
                        for (size_t i = 4; buf[i]; ++i) {
                            buf[i] = tolower(buf[i]);
                        }
                        size_t alloc_size = 64;
                        char* heap_buf = (char*)malloc(alloc_size);
                        if (heap_buf) {
                            strcpy(heap_buf, "prefix-");
                            //SINK
                            strcat(heap_buf, buf);
                            printf("Processed: %s\n", heap_buf);
                            free(heap_buf);
                        }
                    }
                }
                close(fd);
            }
        }
    if (argc < 1)
        return 1;
    cmdline_logging();
    init_argv0(argc, argv);
    umask(0);
    return APPLET_STUB_MAIN(argc, argv);
}
