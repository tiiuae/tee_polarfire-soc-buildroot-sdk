/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "sel4_tool_cmdline.h"

#include "sel4_req.h"
#include "sel4_circ.h"
#include "ree_tee_msg.h"


#define DEVMEM_HANDLE           "/dev/mem"  /* For reading crashmem */
#define CRASHLOG_SIZE           0x2000      /* from devicetree */
#define CRASHLOG_PA             0xA2450000  /* from devicetree */

typedef int sync_spinlock_t; /* seL4 spinlock */

/* memory structure in the beginning of crashlog area */
struct crashlog_hdr {
    struct circ_buf_hdr circ_hdr;
    sync_spinlock_t writer_lock;
    sync_spinlock_t reader_lock;
};

int sel4_read_crashlog(const char *filename)
{
    ssize_t ret = -1;
    int fd = 0;
    int32_t read_len = 0;
    int dummy_lock = 0;

    char *crashlog_area = NULL;

    struct circ_ctx circ = { 0 };

    char *read_buf = malloc(CRASHLOG_SIZE);

    if (!read_buf) {
        printf("ERROR: out of memory: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -ENOMEM;
        goto out;
    }

    if (!filename) {
        printf("ERROR params: %s: %d\n", __FUNCTION__, __LINE__);
        ret = -EINVAL;
        goto out;
    }

    fd = open(DEVMEM_HANDLE, O_RDWR);
    if (fd <= 0) {
        printf("failed to open %s: %d\n", DEVMEM_HANDLE, errno);
        ret = -EIO;
        goto out;
    }

    crashlog_area = mmap(NULL, CRASHLOG_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, CRASHLOG_PA);

    if (crashlog_area == MAP_FAILED) {
        printf("ERROR: mmap: MAP_FAILED\n");
        ret = -EIO;
        goto out;
    }

    printf("crashlog_area: %p\n", crashlog_area);

    /* Setup ctrl struct for CIRC read */
    circ.hdr = (struct circ_buf_hdr *)crashlog_area;
    circ.buf = crashlog_area + sizeof(struct crashlog_hdr);

    ret = sel4_read_from_circ(&circ, CRASHLOG_SIZE, read_buf, &read_len,
                              &dummy_lock);
    if (ret) {
        printf("ERROR: sel4_read_from_circ: %ld\n", ret);
        goto out;
    }

    printf("crashlog size: %d\n", read_len);

    ret = sel4_tool_save_file(filename, (uint8_t *)read_buf, read_len);
    if (ret) {
        goto out;
    }

out:
    munmap(crashlog_area, CRASHLOG_SIZE);

    free(read_buf);

    return ret;
}

