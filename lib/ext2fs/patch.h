/**
 * patch.h --- Common "patch" file functions
 *
 * Patch file format:
 * 1) sparse data blocks - same size as the patched filesystem, but only changed blocks are written
 * 2) updated block bitmap - fs_size/block_size/8 bytes
 * 3) 4 byte FS block size
 * 4) 8 byte FS size in blocks
 *
 * Copyright (c) Vitaliy Filippov <vitalif@mail.ru> 2014
 * License: GNU GPLv2 or later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef E2_PATCH_H
#define E2_PATCH_H

#include "ext2_fs.h"
#include "ext2fs.h"

#define PATCHBD_MAGIC 0x44623950 // P9bD

struct ext2fs_patch_file
{
	char *patch_file;
	int patch_fd;
	__u32 block_size;
	blk64_t size;
	ext2_loff_t offset;
	ext2fs_generic_bitmap bmap;
};

struct patchbd_super
{
	__u32 magic;
	__u32 patch_block;
	__u64 patch_size;
};

errcode_t ext2fs_patch_retry_read(int fd, ssize_t size, void *buf);
errcode_t ext2fs_patch_retry_write(int fd, ssize_t size, const void *buf);
errcode_t ext2fs_patch_retry_read_at(int fd, unsigned long long offset, ssize_t size, void *buf);
errcode_t ext2fs_patch_retry_write_at(int fd, unsigned long long offset, ssize_t size, const void *buf);
errcode_t ext2fs_patch_read_bmap(struct ext2fs_patch_file *data);
errcode_t ext2fs_patch_write_bmap(struct ext2fs_patch_file *data);
errcode_t ext2fs_patch_open(struct ext2fs_patch_file *data, char *patch_file, int flags);
errcode_t ext2fs_patch_close(struct ext2fs_patch_file *data);
errcode_t ext2fs_patch_init_bmap(struct ext2fs_patch_file *data, io_channel channel);
errcode_t ext2fs_patch_write_blk64(struct ext2fs_patch_file *data, unsigned long long block, int count, const void *buf);

#endif
