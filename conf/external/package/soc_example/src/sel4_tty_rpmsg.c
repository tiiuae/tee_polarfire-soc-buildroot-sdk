/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include <stdlib.h>
#include <poll.h>

#include "ree_tee_msg.h"
#include "sel4_tty_rpmsg.h"

#define SEL4TTY "/dev/ttyRPMSG6"

static int open_tty()
{
    int fd = 0;
    struct termios tty = {0};

    fd = open(SEL4TTY, O_RDWR | O_NOCTTY);
    if(fd <= 0)
    {
        printf("failed to open %s: %d\n", SEL4TTY, errno);
        return -EIO;
    }

    /* From https://github.com/polarfire-soc/polarfire-soc-linux-examples/
     *                                       amp/rpmsg-tty-example/rpmsg-tty.c
     */
    tcgetattr(fd, &tty);              /* get current attributes */
    cfmakeraw(&tty);                  /* raw input */
    tty.c_cc[VMIN] = 0;               /* non blocking */
    tty.c_cc[VTIME] = 0;              /* non blocking */
    tcsetattr(fd, TCSANOW, &tty);     /* write attributes */

    return fd;
}

static int tty_read_resp(int tty_fd, struct tty_msg *tty)
{
    int err = -1;
    ssize_t read_bytes = 0;
    ssize_t recv = 0;
    ssize_t msg_len = 0;

    struct pollfd fds = {
        .fd = tty_fd,
        .events = POLLIN,
    };

    struct ree_tee_hdr recv_hdr = { 0 };

    /* Wait until data available in TTY */
    err = poll(&fds, 1, -1);
    if (err < 1)
    {
        printf("ERROR: poll: %d\n", errno);
        err = -EACCES;
        goto err_out;
    }

    /* read header to allocate buffer for whole message */
    recv = read(tty_fd, &recv_hdr, HDR_LEN);
    if (recv != HDR_LEN)
    {
        printf("ERROR: read hdr: %ld (%d)\n", recv, errno);
        err = -EIO;
        goto err_out;
    }

    printf("reply len: %d\n", recv_hdr.length);

    tty->recv_buf = malloc(recv_hdr.length);
    if (!tty->recv_buf)
    {
        printf("ERROR: out of memory: %d\n", __LINE__);
        err = -ENOMEM;
        goto err_out;
    }

    msg_len = recv_hdr.length;
    read_bytes += recv;

    memcpy(tty->recv_buf, &recv_hdr, HDR_LEN);

    while (read_bytes != msg_len) {
        recv = read(tty_fd, tty->recv_buf + read_bytes, msg_len - read_bytes);

        if (recv < 0)
        {
            printf("ERROR: read: %d\n", errno);
            err = -EBUSY;
            goto err_out;
        }

        read_bytes += recv;
    }

    return read_bytes;

err_out:
    if (tty->recv_buf)
    {
        free(tty->recv_buf);
        tty->recv_buf = NULL;
    }

    return err;
}

int tty_req(struct tty_msg *tty)
{
    int err = -1;
    int tty_fd = -1;
    ssize_t recv = 0;

    struct ree_tee_hdr *hdr = NULL;

    tty_fd = open_tty();
    if (tty_fd <= 0)
    {
        err = -EIO;
        goto err_out;
    }

    /*Write message to TEE*/
    if (write(tty_fd, tty->send_buf, tty->send_len) != tty->send_len)
    {
        printf("Writing request failed (%d)\n", errno);
        err = -EIO;
        goto err_out;
    }

    /* Recv TEE reply */
    recv = tty_read_resp(tty_fd, tty);
    if (recv < 0)
    {
        err = recv;
        goto err_out;
    }

    hdr = (struct ree_tee_hdr *)tty->recv_buf;

    if (tty->recv_len != SKIP_LEN_CHECK &&
        tty->recv_len != recv)
    {
        printf("ERROR: invalid msg len: %ld (%d)\n", recv, tty->recv_len);
        err = -EFAULT;
        goto err_out;
    }

    if (tty->recv_msg != REE_TEE_INVALID &&
        tty->recv_msg != hdr->msg_type)
    {
        printf("ERROR: invalid msg type: %d (%d)\n", hdr->msg_type, tty->recv_msg);
        err = -EFAULT;
        goto err_out;
    }

    return recv;

err_out:
    if (tty->recv_buf)
    {
        free(tty->recv_buf);
        tty->recv_buf = NULL;
    }

    return err;
}