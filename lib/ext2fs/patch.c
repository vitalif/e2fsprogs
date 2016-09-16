/**
 * patch.c --- Common "patch" file functions
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

#include <unistd.h>
#include <fcntl.h>
#include "patch.h"

errcode_t ext2fs_patch_retry_read(int fd, ssize_t size, void *buf)
{
	ssize_t r, done = 0;
	while (done < size)
	{
		r = read(fd, buf+done, size-done);
		if (!r || (r < 0 && errno != EAGAIN))
			break;
		done += r;
	}
	if (done < size)
		return errno;
	return 0;
}

errcode_t ext2fs_patch_retry_write(int fd, ssize_t size, const void *buf)
{
	ssize_t r, done = 0;
	while (done < size)
	{
		r = write(fd, buf+done, size-done);
		if (r <= 0 && errno != EAGAIN)
			break;
		done += r;
	}
	if (done < size)
		return errno;
	return 0;
}

errcode_t ext2fs_patch_retry_read_at(int fd, unsigned long long offset, ssize_t size, void *buf)
{
	if ((unsigned long long)ext2fs_llseek(fd, offset, SEEK_SET) != offset)
		return errno ? errno : EXT2_ET_LLSEEK_FAILED;
	return ext2fs_patch_retry_read(fd, size, buf);
}

errcode_t ext2fs_patch_retry_write_at(int fd, unsigned long long offset, ssize_t size, const void *buf)
{
	if ((unsigned long long)ext2fs_llseek(fd, offset, SEEK_SET) != offset)
		return errno ? errno : EXT2_ET_LLSEEK_FAILED;
	return ext2fs_patch_retry_write(fd, size, buf);
}

errcode_t ext2fs_patch_read_bmap(struct ext2fs_patch_file *data)
{
	errcode_t retval = 0;
	int bufsize = 65536;
	blk64_t i, r;
	void *buf = malloc(bufsize);
	if (!buf)
		return ENOMEM;
	ext2fs_llseek(data->patch_fd, data->block_size, SEEK_SET);
	for (i = 0; i < data->size/8; )
	{
		r = bufsize;
		if (data->size/8 - i < r)
			r = data->size/8 - i;
		retval = ext2fs_patch_retry_read(data->patch_fd, r, buf);
		if (retval)
			goto out;
		ext2fs_set_generic_bmap_range(data->bmap, i*8, r*8, buf);
		i += r;
	}
out:
	free(buf);
	return retval;
}

errcode_t ext2fs_patch_write_bmap(struct ext2fs_patch_file *data)
{
	errcode_t retval = 0;
	int bufsize = 65536;
	blk64_t i, r;
	struct patchbd_super s;
	void *buf = malloc(bufsize);
	if (!buf)
		return ENOMEM;
	ext2fs_llseek(data->patch_fd, data->block_size, SEEK_SET);
	for (i = 0; i < data->size/8; )
	{
		r = bufsize;
		if (data->size/8 - i < r)
			r = data->size/8 - i;
		ext2fs_get_generic_bmap_range(data->bmap, i*8, r*8, buf);
		retval = ext2fs_patch_retry_write(data->patch_fd, r, buf);
		if (retval)
			goto out;
		i += r;
	}
	ext2fs_llseek(data->patch_fd, 0, SEEK_SET);
	s.magic = PATCHBD_MAGIC;
	s.patch_block = data->block_size;
	s.patch_size = data->size;
	write(data->patch_fd, &s, sizeof(struct patchbd_super));
out:
	free(buf);
	return 0;
}

errcode_t ext2fs_patch_open(struct ext2fs_patch_file *data, char *patch_file, int flags)
{
	errcode_t retval = 0;
	ext2_loff_t size;
	struct patchbd_super s;
	data->block_size = 0;
	data->size = 0;
	data->offset = 0;
	data->bmap = NULL;
	data->patch_file = strdup(patch_file);
	data->patch_fd = open(data->patch_file, flags|O_RDWR, 0666);
	if (data->patch_fd < 0)
		return errno;
	size = ext2fs_llseek(data->patch_fd, 0, SEEK_END);
	if (size < 0)
		return errno;
	if (size > 0)
	{
		size = ext2fs_llseek(data->patch_fd, 0, SEEK_SET);
		read(data->patch_fd, &s, sizeof(struct patchbd_super));
		if (s.magic != PATCHBD_MAGIC)
			return 0;
		data->block_size = s.patch_block;
//		if (data->block_size != 4096)
//			return EINVAL;
		data->size = s.patch_size;
		retval = ext2fs_patch_init_bmap(data, NULL);
		if (retval)
			return retval;
		retval = ext2fs_patch_read_bmap(data);
	}
	return 0;
}

errcode_t ext2fs_patch_close(struct ext2fs_patch_file *data)
{
	if (data)
	{
		if (data->bmap)
		{
			if (data->patch_fd >= 0)
				ext2fs_patch_write_bmap(data);
			ext2fs_free_generic_bmap(data->bmap);
			data->bmap = NULL;
		}
		if (data->patch_fd >= 0)
		{
			close(data->patch_fd);
			data->patch_fd = -1;
		}
		if (data->patch_file)
		{
			free(data->patch_file);
			data->patch_file = NULL;
		}
	}
	return 0;
}

errcode_t ext2fs_patch_init_bmap(struct ext2fs_patch_file *data, io_channel channel)
{
	errcode_t retval = 0;
	if (!data->bmap)
	{
		if (channel)
		{
			// channel is optional parameter, if passed, means 'take size from channel'
			data->block_size = channel->block_size;
//			if (data->block_size != 4096)
//				return EINVAL;
			retval = ext2fs_get_device_size2(channel->name, data->block_size, &data->size);
			if (retval)
				return retval;
		}
		else if (!data->block_size || !data->size)
			return EINVAL;
		retval = ext2fs_make_generic_bitmap(EXT2_ET_MAGIC_BLOCK_BITMAP, NULL,
			0, data->size, data->size, "overwritten blocks", 0, &data->bmap);
		data->offset = data->block_size + ((((data->size+7)>>3)+(data->block_size-1))&~(data->block_size-1));
	}
	return retval;
}

errcode_t ext2fs_patch_write_blk64(struct ext2fs_patch_file *data, unsigned long long block, int count, const void *buf)
{
	ssize_t size;
	if (!data->bmap)
		return EINVAL;
	if (count < 0)
	{
		if ((unsigned)-count > data->block_size)
			return EINVAL;
		size = -count;
		count = 1;
	}
	else
		size = count*data->block_size;
	ext2fs_mark_block_bitmap_range2(data->bmap, block, count);
	return ext2fs_patch_retry_write_at(data->patch_fd, data->offset + block*data->block_size, size, buf);
}
