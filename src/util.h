#pragma once

#include <fcntl.h>
#include <unistd.h>

static inline int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    if (flags < 0) {
        return -1;
    }

    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static inline int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
