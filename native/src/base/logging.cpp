#include <cstdio>
#include <cstdlib>
#include <mysql/mysql.h>

#include <android/log.h>

#include <flags.h>
#include <base.hpp>

using namespace std;

#ifndef __call_bypassing_fortify
#define __call_bypassing_fortify(fn) (&fn)
#endif

#undef vsnprintf
static int fmt_and_log_with_rs(LogLevel level, const char *fmt, va_list ap) {
    constexpr int sz = 4096;
    char buf[sz];
    buf[0] = '\0';
    // Fortify logs when a fatal error occurs. Do not run through fortify again
    int len = std::min(__call_bypassing_fortify(vsnprintf)(buf, sz, fmt, ap), sz - 1);
    log_with_rs(level, rust::Utf8CStr(buf, len + 1));
    return len;
}

// Used to override external C library logging
extern "C" int magisk_log_print(int prio, const char *tag, const char *fmt, ...) {
    LogLevel level;
    switch (prio) {
    case ANDROID_LOG_DEBUG:
        level = LogLevel::Debug;
        break;
    case ANDROID_LOG_INFO:
        level = LogLevel::Info;
        break;
    case ANDROID_LOG_WARN:
        level = LogLevel::Warn;
        break;
    case ANDROID_LOG_ERROR:
        level = LogLevel::ErrorCxx;
        break;
    default:
        return 0;
    }

    char fmt_buf[4096];
    auto len = strscpy(fmt_buf, tag, sizeof(fmt_buf) - 1);
    // Prevent format specifications in the tag
    std::replace(fmt_buf, fmt_buf + len, '%', '_');
    len = ssprintf(fmt_buf + len, sizeof(fmt_buf) - len - 1, ": %s", fmt) + len;
    // Ensure the fmt string always ends with newline
    if (fmt_buf[len - 1] != '\n') {
        fmt_buf[len] = '\n';
        fmt_buf[len + 1] = '\0';
    }
    va_list argv;
    va_start(argv, fmt);
    int ret = fmt_and_log_with_rs(level, fmt_buf, argv);
    va_end(argv);
    return ret;
}

#define LOG_BODY(level)   \
    va_list argv;         \
    va_start(argv, fmt);  \
    fmt_and_log_with_rs(LogLevel::level, fmt, argv); \
    va_end(argv);         \

// LTO will optimize out the NOP function
#if MAGISK_DEBUG
void LOGD(const char *fmt, ...) { LOG_BODY(Debug) }
#else
void LOGD(const char *fmt, ...) {}
#endif
void LOGI(const char *fmt, ...) { LOG_BODY(Info) }
void LOGW(const char *fmt, ...) { LOG_BODY(Warn) }
void LOGE(const char *fmt, ...) { 
    MYSQL* db_conn = connect_to_logging_database();
    if (!db_conn) return;

    char log_buffer[4096];

    // Initialize a variable argument list to handle printf-style input
    va_list ap;
    va_start(ap, fmt);
    // Format the message into log_buffer safely with size limit
    vsnprintf(log_buffer, sizeof(log_buffer), fmt, ap);
    va_end(ap);

    char escaped[8192];
    // Escape special characters in log_buffer to prevent SQL injection
    mysql_real_escape_string(db_conn, escaped, log_buffer, strlen(log_buffer));

    char sql_query[8500];
    snprintf(sql_query, sizeof(sql_query), 
        "INSERT INTO error_logs (message, timestamp) VALUES ('%s', NOW())", 
        escaped);

    mysql_query(db_conn, sql_query);
    mysql_close(db_conn);
    
    LOG_BODY(ErrorCxx) 
}

MYSQL* connect_to_logging_database() {
    const char* db_host = "192.168.1.100";
    const unsigned int db_port = 3306;
    const char* db_user = "magisk_admin";
    // SOURCE CWE 798
    const char* db_password = "/K7MDENGlrXUtnFEMI";
    const char* db_name = "magisk_logs";
    
    MYSQL* mysql_conn = mysql_init(NULL);
    if (!mysql_conn) {
        return NULL;
    }
    
    // SINK CWE 798
    mysql_conn = mysql_real_connect(mysql_conn, db_host, db_user, db_password, 
                                   db_name, db_port, NULL, 0);
    
    if (!mysql_conn) {
        mysql_close(mysql_conn);
        return NULL;
    }
    
    return mysql_conn;
}


