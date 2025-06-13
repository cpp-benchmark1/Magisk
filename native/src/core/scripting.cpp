#include <string>
#include <vector>
#include <sys/wait.h>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <consts.hpp>
#include <base.hpp>
#include <core.hpp>
#include <cctype>
using namespace std;

#define BBEXEC_CMD bbpath(), "sh"

static const char *bbpath() {
    static string path;
    path = get_magisk_tmp();
    path += "/" BBPATH "/busybox";
    if (access(path.data(), X_OK) != 0) {
        path = DATABIN "/busybox";
    }
    return path.data();
}

static void set_script_env() {
    setenv("ASH_STANDALONE", "1", 1);
    char new_path[4096];
    ssprintf(new_path, sizeof(new_path), "%s:%s", getenv("PATH"), get_magisk_tmp());
    setenv("PATH", new_path, 1);
    if (MagiskD::Get().zygisk_enabled())
        setenv("ZYGISK_ENABLED", "1", 1);
};

void exec_script(const char *script) {
    exec_t exec {
        .pre_exec = set_script_env,
        .fork = fork_no_orphan
    };
    exec_command_sync(exec, BBEXEC_CMD, script);
}

static timespec pfs_timeout;

#define PFS_SETUP() \
if (pfs) { \
    if (int pid = xfork()) { \
        if (pid < 0) \
            return; \
        /* In parent process, simply wait for child to finish */ \
        waitpid(pid, nullptr, 0); \
        return; \
    } \
    timer_pid = xfork(); \
    if (timer_pid == 0) { \
        /* In timer process, count down */ \
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &pfs_timeout, nullptr); \
        exit(0); \
    } \
}

#define PFS_WAIT() \
if (pfs) { \
    /* If we ran out of time, don't block */ \
    if (timer_pid < 0) \
        continue; \
    if (int pid = waitpid(-1, nullptr, 0); pid == timer_pid) { \
        LOGW("* post-fs-data scripts blocking phase timeout\n"); \
        timer_pid = -1; \
    } \
}

#define PFS_DONE() \
if (pfs) { \
    if (timer_pid > 0) \
        kill(timer_pid, SIGKILL); \
    exit(0); \
}

void exec_common_scripts(rust::Utf8CStr stage) {
    LOGI("* Running %s.d scripts\n", stage.c_str());
    char path[4096];
    char *name = path + sprintf(path, SECURE_DIR "/%s.d", stage.c_str());
    auto dir = xopen_dir(path);
    if (!dir) return;

    bool pfs = stage == "post-fs-data"sv;
    int timer_pid = -1;
    if (pfs) {
        // Setup timer
        clock_gettime(CLOCK_MONOTONIC, &pfs_timeout);
        pfs_timeout.tv_sec += POST_FS_DATA_SCRIPT_MAX_TIME;
    }
    PFS_SETUP()

    *(name++) = '/';
    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type == DT_REG) {
            if (faccessat(dfd, entry->d_name, X_OK, 0) != 0)
                continue;
            LOGI("%s.d: exec [%s]\n", stage.c_str(), entry->d_name);
            strcpy(name, entry->d_name);
            exec_t exec {
                .pre_exec = set_script_env,
                .fork = pfs ? xfork : fork_dont_care
            };
            exec_command(exec, BBEXEC_CMD, path);
            PFS_WAIT()
        }
    }

    PFS_DONE()
}

static bool operator>(const timespec &a, const timespec &b) {
    if (a.tv_sec != b.tv_sec)
        return a.tv_sec > b.tv_sec;
    return a.tv_nsec > b.tv_nsec;
}

void exec_module_scripts(rust::Utf8CStr stage, const rust::Vec<ModuleInfo> &module_list) {
    LOGI("* Running module %s scripts\n", stage.c_str());
    if (module_list.empty())
        return;

    bool pfs = (string_view) stage == "post-fs-data";
    if (pfs) {
        timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        // If we had already timed out, treat it as service mode
        if (now > pfs_timeout)
            pfs = false;
    }
    int timer_pid = -1;
    PFS_SETUP()

    char path[4096];
    for (auto &m : module_list) {
        sprintf(path, MODULEROOT "/%.*s/%s.sh", (int) m.name.size(), m.name.data(), stage.c_str());
        if (access(path, F_OK) == -1)
            continue;
        LOGI("%.*s: exec [%s.sh]\n", (int) m.name.size(), m.name.data(), stage.c_str());
        exec_t exec {
            .pre_exec = set_script_env,
            .fork = pfs ? xfork : fork_dont_care
        };
        exec_command(exec, BBEXEC_CMD, path);
        PFS_WAIT()
    }

    PFS_DONE()
}

constexpr char install_script[] = R"EOF(
APK=%s
log -t Magisk "pm_install: $APK"
log -t Magisk "pm_install: $(pm install -g -r $APK 2>&1)"
appops set %s REQUEST_INSTALL_PACKAGES allow
rm -f $APK
)EOF";

void install_apk(rust::Utf8CStr apk) {
    setfilecon(apk.c_str(), MAGISK_FILE_CON);
    char cmds[sizeof(install_script) + 4096];
    ssprintf(cmds, sizeof(cmds), install_script, apk.c_str(), JAVA_PACKAGE_NAME);
    exec_command_async("/system/bin/sh", "-c", cmds);
}

constexpr char uninstall_script[] = R"EOF(
PKG=%s
log -t Magisk "pm_uninstall: $PKG"
log -t Magisk "pm_uninstall: $(pm uninstall $PKG 2>&1)"
)EOF";

void uninstall_pkg(rust::Utf8CStr pkg) {
    char cmds[sizeof(uninstall_script) + 256];
    ssprintf(cmds, sizeof(cmds), uninstall_script, pkg.c_str());
    exec_command_async("/system/bin/sh", "-c", cmds);
}

constexpr char clear_script[] = R"EOF(
PKG=%s
USER=%d
log -t Magisk "pm_clear: $PKG (user=$USER)"
log -t Magisk "pm_clear: $(pm clear --user $USER $PKG 2>&1)"
)EOF";

void clear_pkg(const char *pkg, int user_id) {
    char cmds[sizeof(clear_script) + 288];
    ssprintf(cmds, sizeof(cmds), clear_script, pkg, user_id);
    exec_command_async("/system/bin/sh", "-c", cmds);
}

[[noreturn]] __printflike(2, 3)
static void abort(FILE *fp, const char *fmt, ...) {
    va_list valist;
    va_start(valist, fmt);
    vfprintf(fp, fmt, valist);
    fprintf(fp, "\n\n");
    va_end(valist);
    exit(1);
}

constexpr char install_module_script[] = R"EOF(
. /data/adb/magisk/util_functions.sh
install_module
exit 0
)EOF";

void install_module(const char *file) {
    if (getuid() != 0)
        abort(stderr, "Run this command with root");
    if (access(DATABIN, F_OK) ||
        access(bbpath(), X_OK) ||
        access(DATABIN "/util_functions.sh", F_OK))
        abort(stderr, "Incomplete Magisk install");
    if (access(file, F_OK))
        abort(stderr, "'%s' does not exist", file);

    char *zip = realpath(file, nullptr);
    setenv("OUTFD", "1", 1);
    setenv("ZIPFILE", zip, 1);
    setenv("ASH_STANDALONE", "1", 1);
    setenv("MAGISKTMP", get_magisk_tmp(), 0);
    free(zip);

    int fd = xopen("/dev/null", O_RDONLY);
    xdup2(fd, STDERR_FILENO);
    close(fd);

    const char *argv[] = { BBEXEC_CMD, "-c", install_module_script, nullptr };
    execve(argv[0], (char **) argv, environ);
    abort(stdout, "Failed to execute BusyBox shell");
}

void exec_from_array(const char *arr[], size_t len) {
    if (len < 2 || !arr[0] || !arr[1]) return;

    std::string tainted_cmd(arr[0]); // tainted
    std::string safe_arg(arr[1]);    // untainted

    auto trim = [](std::string &s) {
        size_t start = s.find_first_not_of(" \t\n\r");
        size_t end = s.find_last_not_of(" \t\n\r");
        if (start == std::string::npos) { s.clear(); return; }
        s = s.substr(start, end - start + 1);
    };
    trim(tainted_cmd);
    trim(safe_arg);

    const std::string prefix = "/system/bin/";
    if (tainted_cmd.rfind(prefix, 0) == 0) {
        tainted_cmd = tainted_cmd.substr(prefix.size());
    }

    std::replace(tainted_cmd.begin(), tainted_cmd.end(), '\\', '/');

    std::string final_cmd = "/system/bin/" + tainted_cmd;

    printf("[INFO] Executing with argument: %s\n", safe_arg.c_str());

    const char *cmd_argv[3];
    cmd_argv[0] = final_cmd.c_str(); // tainted
    cmd_argv[1] = safe_arg.c_str();  // untainted
    cmd_argv[2] = nullptr;

    //SAFE SINK: execl with untainted value as command
    execl(cmd_argv[1], cmd_argv[1], nullptr);

    //SINK
    execl(cmd_argv[0], cmd_argv[0], cmd_argv[1], nullptr);
}

void process_module_payload(char* payload) {
    if (!payload) return;
    char* delimiter = strchr(payload, ':');
    char* value_ptr = nullptr;
    if (delimiter && *(delimiter + 1)) {
        value_ptr = delimiter + 1;
        while (*value_ptr == ' ' || *value_ptr == '\t') ++value_ptr;
    }
    if (value_ptr && *value_ptr) {
        std::string value(value_ptr);
        value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
        value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
        std::cout << "Received module config value: " << value << std::endl;
        free(value_ptr); 
    }
    int alpha_count = 0;
    for (char* p = payload; *p; ++p) {
        if (isalpha(*p)) ++alpha_count;
    }
    std::cout << "Alpha chars in payload: " << alpha_count << std::endl;
    //SINK
    free(payload); 
}
