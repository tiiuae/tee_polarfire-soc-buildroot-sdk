/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_TOOL_CMDLINE_H_
#define _SEL4_TOOL_CMDLINE_H_

#include <stdint.h>

enum tool_cmd {
    TOOL_CMD_INVALID = 0,
    TOOL_CMD_GENERATE_KEYS,
    TOOL_CMD_EXPORT_KEY,
};

int sel4_tool_load_file(char *storage_path, uint8_t **storage, uint32_t *storage_len);
int sel4_tool_save_file(char *storage_path, uint8_t *storage, uint32_t storage_len);
int sel4_tool_parse_opts(int argc, char* argv[], char **infile, char **outfile, uint32_t *cmd);

#endif /* _SEL4_TOOL_CMDLINE_H_ */