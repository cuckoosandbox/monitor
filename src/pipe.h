#ifndef MONITOR_PIPE_H
#define MONITOR_PIPE_H

//
// Pipe API
//
// The following Format Specifiers are available:
// z  -> (char *) -> zero-terminated ascii string
// Z  -> (wchar_t *) -> zero-terminated unicode string
// s  -> (int, char *) -> ascii string with length
// S  -> (int, wchar_t *) -> unicode string with length
// o  -> (UNICODE_STRING *) -> unicode string
// O  -> (OBJECT_ATTRIBUTES *) -> wrapper around unicode string
// d  -> (int) -> integer
// x  -> (int) -> hexadecimal integer
//

void pipe_init(const char *pipe_name);

int pipe(const char *fmt, ...);
int pipe2(void *out, int *outlen, const char *fmt, ...);

#define PIPE_MAX_TIMEOUT 10000

#endif
