/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

struct nft_ctx;

enum nft_debug_level {
	NFT_DEBUG_SCANNER		= 0x1,
	NFT_DEBUG_PARSER		= 0x2,
	NFT_DEBUG_EVALUATION		= 0x4,
	NFT_DEBUG_NETLINK		= 0x8,
	NFT_DEBUG_MNL			= 0x10,
	NFT_DEBUG_PROTO_CTX		= 0x20,
	NFT_DEBUG_SEGTREE		= 0x40,
};

enum nft_numeric_level {
	NFT_NUMERIC_NONE,
	NFT_NUMERIC_ADDR,
	NFT_NUMERIC_PORT,
	NFT_NUMERIC_ALL,
};

/**
 * Possible flags to pass to nft_ctx_new()
 */
#define NFT_CTX_DEFAULT		0

struct nft_ctx *nft_ctx_new(uint32_t flags);
void nft_ctx_free(struct nft_ctx *ctx);

bool nft_ctx_get_dry_run(struct nft_ctx *ctx);
void nft_ctx_set_dry_run(struct nft_ctx *ctx, bool dry);
enum nft_numeric_level nft_ctx_output_get_numeric(struct nft_ctx *ctx);
void nft_ctx_output_set_numeric(struct nft_ctx *ctx, enum nft_numeric_level level);
bool nft_ctx_output_get_stateless(struct nft_ctx *ctx);
void nft_ctx_output_set_stateless(struct nft_ctx *ctx, bool val);
bool nft_ctx_output_get_ip2name(struct nft_ctx *ctx);
void nft_ctx_output_set_ip2name(struct nft_ctx *ctx, bool val);
unsigned int nft_ctx_output_get_debug(struct nft_ctx *ctx);
void nft_ctx_output_set_debug(struct nft_ctx *ctx, unsigned int mask);
bool nft_ctx_output_get_handle(struct nft_ctx *ctx);
void nft_ctx_output_set_handle(struct nft_ctx *ctx, bool val);
bool nft_ctx_output_get_echo(struct nft_ctx *ctx);
void nft_ctx_output_set_echo(struct nft_ctx *ctx, bool val);

FILE *nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp);
int nft_ctx_add_include_path(struct nft_ctx *ctx, const char *path);
void nft_ctx_clear_include_paths(struct nft_ctx *ctx);

int nft_run_cmd_from_buffer(struct nft_ctx *nft, char *buf, size_t buflen);
int nft_run_cmd_from_filename(struct nft_ctx *nft, const char *filename);

#endif /* LIB_NFTABLES_H */
