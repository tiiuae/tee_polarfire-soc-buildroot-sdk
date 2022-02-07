/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_REQ_H_
#define _SEL4_REQ_H_

#include <stdint.h>

int sel4_read_crashlog(const char *filename);

#endif /* _SEL4_REQ_H_ */