/* Stop a disposable Mail process during Sent file publication or removal. */
#if defined(__linux__)
#define _GNU_SOURCE
#include <dlfcn.h>
#endif
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void stop_at_sent_boundary(int fd)
{
    const char *target = getenv("MAIL_TEST_SENT_DIRECTORY");
    const char *phase = getenv("MAIL_TEST_SENT_BOUNDARY");
    if (!target || !phase)
        return;
    char path[PATH_MAX];
#if defined(__APPLE__)
    if (fcntl(fd, F_GETPATH, path) == -1)
        return;
#elif defined(__linux__)
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link, path, sizeof(path) - 1);
    if (size < 0)
        return;
    path[size] = '\0';
#else
#error "Sent crash fixture supports Darwin and Linux"
#endif
    const char *sent = strstr(path, target);
    if (!sent)
        return;
    const char *suffix = sent + strlen(target);
    if ((strcmp(phase, "before-link") == 0 && strncmp(suffix, "/.pending-", 10) == 0) ||
        (*suffix == '\0' && (strcmp(phase, "after-link") == 0 ||
         (strcmp(phase, "after-discard") == 0 && access("remote-refused", F_OK) == 0))))
        raise(SIGSTOP);
}

#if defined(__APPLE__)
static int hooked_fsync(int fd)
{
    int rc = fsync(fd);
    if (rc == 0)
        stop_at_sent_boundary(fd);
    return rc;
}

__attribute__((used, section("__DATA,__interpose")))
static const struct {
    int (*replacement)(int);
    int (*original)(int);
} interpose = { hooked_fsync, fsync };
#elif defined(__linux__)
int fsync(int fd)
{
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    if (!real_fsync)
        _exit(125);
    int rc = real_fsync(fd);
    if (rc == 0)
        stop_at_sent_boundary(fd);
    return rc;
}
#endif
