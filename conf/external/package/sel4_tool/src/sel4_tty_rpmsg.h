/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_TTY_RPMSG_H_
#define _SEL4_TTY_RPMSG_H_

#include <stdint.h>
#include <stdio.h>

#define HDR_LEN             sizeof(struct ree_tee_hdr)

#define SKIP_LEN_CHECK      0

struct tty_msg {
    char *send_buf;
    size_t send_len;

    char *recv_buf;
    uint32_t recv_len;  /* expected response length (SKIP_LEN_CHECK) */
    int32_t recv_msg;   /* expected response msg */
};

int tty_req(struct tty_msg *tty);

#endif /* _SEL4_TTY_RPMSG_H_ */