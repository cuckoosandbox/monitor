#ifndef MONITOR_LOG_H
#define MONITOR_LOG_H

void log_init(unsigned int ip, unsigned short port);
void log_free();

void log_explain();

void log_api(int index, int is_success, int return_value,
    const char *fmt, ...);

void log_anomaly(const char *subcategory, int success,
    const char *funcname, const char *msg);

void log_new_process();
void log_new_thread();

#endif
