/*
 * patch_io.c --- This is the "patch" io manager that writes the new data into
 * a separate sparse file to apply it later.
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

#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "ext2_fs.h"
#include "ext2fs.h"

#include "patch.h"

#ifdef __GNUC__
#define ATTR(x) __attribute__(x)
#else
#define ATTR(x)
#endif

#define EXT2_CHECK_MAGIC(struct, code) if ((struct)->magic != (code)) return (code)

struct patch_private_data
{
	int magic;
	struct ext2fs_patch_file patch;
	/* The backing io channel */
	io_channel real;
	/* to support offset in unix I/O manager */
	ext2_loff_t offset;
};

static errcode_t patch_open(const char *name, int flags, io_channel *channel);
static errcode_t patch_close(io_channel channel);
static errcode_t patch_set_blksize(io_channel channel, int blksize);
static errcode_t patch_read_blk64(io_channel channel, unsigned long long block, int count, void *data);
static errcode_t patch_write_blk64(io_channel channel, unsigned long long block, int count, const void *data);
static errcode_t patch_read_blk(io_channel channel, unsigned long block, int count, void *data);
static errcode_t patch_write_blk(io_channel channel, unsigned long block, int count, const void *data);
static errcode_t patch_flush(io_channel channel);
static errcode_t patch_write_byte(io_channel channel, unsigned long offset, int size, const void *data);
static errcode_t patch_set_option(io_channel channel, const char *option, const char *arg);
static errcode_t patch_get_stats(io_channel channel, io_stats *stats);

static struct struct_io_manager struct_patch_manager = {
	EXT2_ET_MAGIC_IO_MANAGER,
	"Patch I/O Manager",
	patch_open,
	patch_close,
	patch_set_blksize,
	patch_read_blk,
	patch_write_blk,
	patch_flush,
	patch_write_byte,
	patch_set_option,
	patch_get_stats,
	patch_read_blk64,
	patch_write_blk64,
};

io_manager patch_io_manager = &struct_patch_manager;
static char *patch_file;
static io_manager patch_io_backing_manager;

errcode_t set_patch_io_backing_manager(io_manager manager)
{
	patch_io_backing_manager = manager;
	return 0;
}

errcode_t set_patch_io_patch_file(char *file)
{
	patch_file = file;
	return 0;
}

static errcode_t patch_open(const char *name, int flags, io_channel *channel)
{
	io_channel io = NULL;
	struct patch_private_data *data = NULL;
	errcode_t retval;

	if (name == 0)
		return EXT2_ET_BAD_DEVICE_NAME;
	retval = ext2fs_get_mem(sizeof(struct struct_io_channel), &io);
	if (retval)
		goto cleanup;
	memset(io, 0, sizeof(struct struct_io_channel));
	io->magic = EXT2_ET_MAGIC_IO_CHANNEL;
	retval = ext2fs_get_mem(sizeof(struct patch_private_data), &data);
	if (retval)
		goto cleanup;

	io->manager = patch_io_manager;
	retval = ext2fs_get_mem(strlen(name)+1, &io->name);
	if (retval)
		goto cleanup;

	strcpy(io->name, name);
	io->private_data = data;
	io->block_size = 1024;
	io->read_error = 0;
	io->write_error = 0;
	io->refcount = 1;

	memset(data, 0, sizeof(struct patch_private_data));
	data->magic = EXT2_ET_MAGIC_UNIX_IO_CHANNEL;

	if (patch_io_backing_manager)
	{
		retval = patch_io_backing_manager->open(name, flags & ~IO_FLAG_RW, &data->real);
		if (retval)
			goto cleanup;
	}

	if (patch_file)
	{
		retval = ext2fs_patch_open(&data->patch, patch_file, O_CREAT);
		if (retval)
			goto cleanup;
		if (data->patch.block_size)
		{
			retval = io_channel_set_blksize(data->real, data->patch.block_size);
			if (retval)
				goto cleanup;
		}
	}

	*channel = io;
	return 0;

cleanup:
	if (data)
	{
		ext2fs_patch_close(&data->patch);
		if (data->real)
			io_channel_close(data->real);
		ext2fs_free_mem(&data);
	}
	if (io)
	{
		if (io->name)
			ext2fs_free_mem(&io->name);
		ext2fs_free_mem(&io);
	}
	return retval;
}

static errcode_t patch_close(io_channel channel)
{
	struct patch_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	if (--channel->refcount > 0)
		return 0;

	ext2fs_patch_close(&data->patch);
	if (data->real)
		retval = io_channel_close(data->real);
	ext2fs_free_mem(&channel->private_data);
	if (channel->name)
		ext2fs_free_mem(&channel->name);
	ext2fs_free_mem(&channel);

	return retval;
}

static errcode_t patch_set_blksize(io_channel channel, int blksize)
{
	struct patch_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	channel->block_size = (unsigned)blksize;
	if (data->patch.block_size && data->patch.block_size != (unsigned)blksize)
		return EINVAL;
	if (data->real)
		retval = io_channel_set_blksize(data->real, blksize);
	return retval;
}

static errcode_t patch_read_blk64(io_channel channel, unsigned long long block, int count, void *buf)
{
	errcode_t retval = 0;
	struct patch_private_data *data;
	int b, n;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	if (count < 0)
	{
		if (-count <= channel->block_size)
		{
			if (data->patch.bmap && ext2fs_test_generic_bitmap(data->patch.bmap, block))
				retval = ext2fs_patch_retry_read_at(data->patch.patch_fd, data->patch.offset + block*channel->block_size, -count, buf);
			else
				retval = io_channel_read_blk64(data->real, block, count, buf);
			return retval;
		}
		else
			return EINVAL;
	}
	for (b = 0; b < count; )
	{
		for (n = 0; (b+n < count) && data->patch.bmap && ext2fs_test_generic_bitmap(data->patch.bmap, block+b+n); n++) {}
		if (n > 0)
		{
			retval = ext2fs_patch_retry_read_at(data->patch.patch_fd, data->patch.offset + (block+b)*channel->block_size, n*channel->block_size, buf+b*channel->block_size);
			if (retval)
				break;
			b += n;
		}
		for (n = 0; (b+n < count) && (!data->patch.bmap || !ext2fs_test_generic_bitmap(data->patch.bmap, block+b+n)); n++) {}
		if (n > 0)
		{
			retval = io_channel_read_blk64(data->real, block+b, n, buf+b*channel->block_size);
			if (retval)
				break;
			b += n;
		}
	}

	return retval;
}

static errcode_t patch_read_blk(io_channel channel, unsigned long block, int count, void *buf)
{
	return patch_read_blk64(channel, block, count, buf);
}

static errcode_t patch_write_blk64(io_channel channel, unsigned long long block, int count, const void *buf)
{
	struct patch_private_data *data;
	errcode_t retval = 0;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	retval = ext2fs_patch_init_bmap(&data->patch, channel);
	if (retval)
		return retval;
	// libext2fs changes block size to 1024 in order to write the superblock, so we must support it...
	if ((__u32)channel->block_size < data->patch.block_size)
	{
		void *buf2 = NULL;
		unsigned long long block_real = block / (data->patch.block_size / channel->block_size);
		int count_real = ( (block % (data->patch.block_size / channel->block_size))
			+ (count > 0 ? count*channel->block_size : -count)
			+ data->patch.block_size - 1 ) / data->patch.block_size;
		retval = ext2fs_get_mem(count_real * data->patch.block_size, &buf2);
		if (retval)
			goto out;
		retval = patch_read_blk64(channel, block_real, count_real, buf2);
		if (retval)
			goto out;
		memcpy(buf2 + (block % (data->patch.block_size / channel->block_size)) * channel->block_size,
			buf, (count > 0 ? count*channel->block_size : -count));
		retval = ext2fs_patch_write_blk64(&data->patch, block_real, count_real, buf2);
out:
		if (buf2)
			ext2fs_free_mem(&buf2);
		return retval;
	}
	else if ((__u32)channel->block_size > data->patch.block_size)
	{
		return EXT2_ET_UNIMPLEMENTED;
	}
	return ext2fs_patch_write_blk64(&data->patch, block, count, buf);
}

static errcode_t patch_write_blk(io_channel channel, unsigned long block, int count, const void *buf)
{
	return patch_write_blk64(channel, block, count, buf);
}

static errcode_t patch_write_byte(io_channel channel, unsigned long offset, int size, const void *buf)
{
	return EXT2_ET_UNIMPLEMENTED;
}

/*
 * Flush data buffers to disk.
 */
static errcode_t patch_flush(io_channel channel)
{
	errcode_t retval = 0;
	struct patch_private_data *data;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	if (data->real)
		retval = io_channel_flush(data->real);
	if (data->patch.patch_fd)
		fsync(data->patch.patch_fd);

	return retval;
}

static errcode_t patch_set_option(io_channel channel, const char *option, const char *arg)
{
	errcode_t retval = 0;
	struct patch_private_data *data;
	unsigned long tmp;
	char *end;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	/*
	 * Need to support offset option to work with
	 * Unix I/O manager
	 */
	if (data->real && data->real->manager->set_option)
		retval = data->real->manager->set_option(data->real, option, arg);
	if (!retval && !strcmp(option, "offset"))
	{
		if (!arg)
			return EXT2_ET_INVALID_ARGUMENT;

		tmp = strtoul(arg, &end, 0);
		if (*end)
			return EXT2_ET_INVALID_ARGUMENT;
		data->offset = tmp;
	}
	return retval;
}

static errcode_t patch_get_stats(io_channel channel, io_stats *stats)
{
	errcode_t retval = 0;
	struct patch_private_data *data;

	EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
	data = (struct patch_private_data *) channel->private_data;
	EXT2_CHECK_MAGIC(data, EXT2_ET_MAGIC_UNIX_IO_CHANNEL);

	if (data->real)
		retval = (data->real->manager->get_stats)(data->real, stats);

	return retval;
}
