/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_TOOL_CMDLINE_H_
#define _SEL4_TOOL_CMDLINE_H_

#include <stdint.h>


int sel4_tool_load_file(char *storage_path, uint8_t **storage, uint32_t *storage_len);
int sel4_tool_save_file(char *storage_path, uint8_t *storage, uint32_t storage_len);

#endif /* _SEL4_TOOL_CMDLINE_H_ */