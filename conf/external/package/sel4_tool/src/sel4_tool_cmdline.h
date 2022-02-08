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
    TOOL_CMD_GENERATE_RSA_PLAINTEXT,
    TOOL_CMD_GENERATE_RSA_CIPHERED,
    TOOL_CMD_EXPORT_KEY,
    TOOL_CMD_IMPORT_KEY,
    TOOL_CMD_READ_CRASHLOG,
};

int sel4_tool_load_file(const char *storage_path, uint8_t **storage, uint32_t *storage_len);
int sel4_tool_save_file(const char *storage_path, uint8_t *storage, uint32_t storage_len);
int sel4_tool_parse_opts(int argc, char* argv[], char **infile, char **outfile, uint32_t *cmd);

#endif /* _SEL4_TOOL_CMDLINE_H_ */