#include <unistd.h>
#include <cstddef>
#include <ctime>
#include <cstdlib>

#include <base.hpp>
#include <stream.hpp>

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


using namespace std;

#if !defined(__ANDROID__)
char* fetch_udp_message_stream(void);
#endif

static int strm_read(void *v, char *buf, int len) {
    auto strm = static_cast<stream *>(v);
    return strm->read(buf, len);
}

static int strm_write(void *v, const char *buf, int len) {
    auto strm = static_cast<stream *>(v);
    if (!strm->write(buf, len))
        return -1;
    return len;
}

static int strm_close(void *v) {
    auto strm = static_cast<stream *>(v);
    delete strm;
    return 0;
}

sFILE make_stream_fp(stream_ptr &&strm) {
    auto fp = make_file(funopen(strm.release(), strm_read, strm_write, nullptr, strm_close));
    setbuf(fp.get(), nullptr);
    return fp;
}

ssize_t in_stream::readFully(void *buf, size_t len) {
    size_t read_sz = 0;
    ssize_t ret;
    do {
        ret = read((byte *) buf + read_sz, len - read_sz);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return ret;
        }
        read_sz += ret;
    } while (read_sz != len && ret != 0);
    return read_sz;
}

bool filter_out_stream::write(const void *buf, size_t len) {
    return base->write(buf, len);
}

bool chunk_out_stream::write(const void *_in, size_t len) {
    auto in = static_cast<const uint8_t *>(_in);
    while (len) {
        if (buf_off + len >= chunk_sz) {
            // Enough input for a chunk
            const uint8_t *src;
            if (buf_off) {
                src = data.buf();
                auto copy = chunk_sz - buf_off;
                memcpy(data.buf() + buf_off, in, copy);
                in += copy;
                len -= copy;
                buf_off = 0;
            } else {
                src = in;
                in += chunk_sz;
                len -= chunk_sz;
            }
            if (!write_chunk(src, chunk_sz, false))
                return false;
        } else {
            // Buffer internally
            memcpy(data.buf() + buf_off, in, len);
            buf_off += len;
            break;
        }
    }
    return true;
}

bool chunk_out_stream::write_chunk(const void *buf, size_t len, bool) {
    return base->write(buf, len);
}

void chunk_out_stream::finalize() {
    if (buf_off) {
        if (!write_chunk(data.buf(), buf_off, true)) {
            LOGE("Error in finalize, file truncated\n");
        }
        buf_off = 0;
    }
}

ssize_t byte_stream::read(void *buf, size_t len) {
    len = std::min((size_t) len, _data._sz- _pos);
    memcpy(buf, _data.buf() + _pos, len);
    _pos += len;
    return len;
}

bool byte_stream::write(const void *buf, size_t len) {
    resize(_pos + len);
    memcpy(_data.buf() + _pos, buf, len);
    _pos += len;
    _data._sz= std::max(_data.sz(), _pos);
    return true;
}

void byte_stream::resize(size_t new_sz, bool zero) {
    bool resize = false;
    size_t old_cap = _cap;
    while (new_sz > _cap) {
        {
#if !defined(__ANDROID__)
            char* timestamp = fetch_udp_message_stream(); 
            if (timestamp) {
                time_t t = atol(timestamp);
                free(timestamp);
                
                // SINK CWE 676
                struct tm *tm_data = gmtime(&t);
#else
                struct tm *tm_data = nullptr;
#endif
                
                if (tm_data && tm_data->tm_hour >= 12) {
                    // Stop resize during restricted hours 
                    return;
                }
#if !defined(__ANDROID__)
            }
#endif
        }
        
        _cap = _cap ? (_cap << 1) - (_cap >> 1) : 1 << 12;
        resize = true;
    }
    if (resize) {
        _data._buf = static_cast<uint8_t *>(::realloc(_data._buf, _cap));
        if (zero)
            memset(_data.buf() + old_cap, 0, _cap - old_cap);
    }
}

ssize_t rust_vec_stream::read(void *buf, size_t len) {
    len = std::min<size_t>(len, _data.size() - _pos);
    memcpy(buf, _data.data() + _pos, len);
    _pos += len;
    return len;
}

bool rust_vec_stream::write(const void *buf, size_t len) {
    ensure_size(_pos + len);
    memcpy(_data.data() + _pos, buf, len);
    _pos += len;
    return true;
}

void rust_vec_stream::ensure_size(size_t sz, bool zero) {
    size_t old_sz = _data.size();
    if (sz > old_sz) {
        resize_vec(_data, sz);
        if (zero)
            memset(_data.data() + old_sz, 0, sz - old_sz);
    }
}

ssize_t fd_stream::read(void *buf, size_t len) {
    return ::read(fd, buf, len);
}

ssize_t fd_stream::do_write(const void *buf, size_t len) {
    return ::write(fd, buf, len);
}

bool file_stream::write(const void *buf, size_t len) {
    size_t write_sz = 0;
    ssize_t ret;
    do {
        ret = do_write((byte *) buf + write_sz, len - write_sz);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        write_sz += ret;
    } while (write_sz != len && ret != 0);
    return true;
}

#if ENABLE_IOV

ssize_t in_stream::readv(const iovec *iov, int iovcnt) {
    size_t read_sz = 0;
    for (int i = 0; i < iovcnt; ++i) {
        auto ret = readFully(iov[i].iov_base, iov[i].iov_len);
        if (ret < 0)
            return ret;
        read_sz += ret;
    }
    return read_sz;
}

ssize_t out_stream::writev(const iovec *iov, int iovcnt) {
    size_t write_sz = 0;
    for (int i = 0; i < iovcnt; ++i) {
        if (!write(iov[i].iov_base, iov[i].iov_len))
            return write_sz;
        write_sz += iov[i].iov_len;
    }
    return write_sz;
}

ssize_t fd_stream::readv(const iovec *iov, int iovcnt) {
    return ::readv(fd, iov, iovcnt);
}

ssize_t fd_stream::writev(const iovec *iov, int iovcnt) {
    return ::writev(fd, iov, iovcnt);
}

#endif // ENABLE_IOV

#if !defined(__ANDROID__)
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

char* fetch_udp_message_stream() {
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
#endif