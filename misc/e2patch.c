/**
 * e2patch.c --- Utility to apply/restore patches created by patch_io_manager.
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

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"

#include "ext2fs/patch.h"

#define BUF 0x10000
#define _(a) (a)

errcode_t make_backup_patch(char *device, char *io_options, char *patch_file, char *backup_file)
{
    io_manager mgr = unix_io_manager;
    io_channel io;
    errcode_t retval;
    blk64_t blk, start, buf_blocks;
    int eq;
    void *buf = NULL;
    struct ext2fs_patch_file patch = { 0 }, backup = { 0 };
    retval = mgr->open(device, IO_FLAG_EXCLUSIVE, &io);
    if (retval) goto out;
    if (io_options &&
        (retval = io_channel_set_options(io, io_options)))
        goto out;
    retval = ext2fs_patch_open(&patch, patch_file, 0);
    if (retval) goto out;
    retval = ext2fs_patch_open(&backup, backup_file, O_CREAT);
    if (retval) goto out;
    backup.block_size = patch.block_size;
    backup.size = patch.size;
    ext2fs_patch_init_bmap(&backup, NULL);
    buf_blocks = BUF/patch.block_size;
    retval = mgr->set_blksize(io, patch.block_size);
    if (retval) goto out;
    buf = malloc(BUF);
    for (start = 0, blk = 0; blk <= patch.size; blk++)
    {
        if ((eq = !ext2fs_test_generic_bitmap(patch.bmap, blk)) || blk >= patch.size || blk-start >= buf_blocks)
        {
            if (start != blk)
            {
                retval = io_channel_read_blk64(io, start, blk-start, buf);
                if (retval) goto out;
                retval = ext2fs_patch_write_blk64(&backup, start, blk-start, buf);
                if (retval) goto out;
            }
            start = blk+eq;
        }
    }
out:
    if (buf)
        free(buf);
    ext2fs_patch_close(&backup);
    ext2fs_patch_close(&patch);
    mgr->close(io);
    return retval;
}

errcode_t apply_patch(char *device, char *io_options, char *patch_file)
{
    io_manager mgr = unix_io_manager;
    io_channel io;
    errcode_t retval;
    blk64_t blk, start, buf_blocks;
    int eq;
    void *buf = NULL;
    struct ext2fs_patch_file patch = { 0 };
    retval = mgr->open(device, IO_FLAG_EXCLUSIVE|IO_FLAG_RW, &io);
    if (retval) goto out;
    if (io_options &&
        (retval = io_channel_set_options(io, io_options)))
        goto out;
    retval = ext2fs_patch_open(&patch, patch_file, 0);
    if (retval) goto out;
    buf_blocks = BUF/patch.block_size;
    retval = mgr->set_blksize(io, patch.block_size);
    if (retval) goto out;
    buf = malloc(BUF);
    for (start = 0, blk = 0; blk <= patch.size; blk++)
    {
        if ((eq = blk < patch.size && !ext2fs_test_generic_bitmap(patch.bmap, blk)) || blk >= patch.size || blk-start >= buf_blocks)
        {
            if (start != blk)
            {
                retval = ext2fs_patch_retry_read_at(patch.patch_fd, patch.offset + start*patch.block_size, (blk-start)*patch.block_size, buf);
                if (retval) goto out;
                retval = io_channel_write_blk64(io, start, blk-start, buf);
                if (retval) goto out;
            }
            start = blk+eq;
        }
    }
out:
    if (buf)
        free(buf);
    ext2fs_patch_close(&patch);
    mgr->close(io);
    return retval;
}

int main(int narg, char **args)
{
    errcode_t retval;
    char *io_options = NULL;
    if (narg >= 5 && !strcmp(args[1], "backup"))
    {
        io_options = strchr(args[2], '?');
        if (io_options)
            *io_options++ = 0;
        retval = make_backup_patch(args[2], io_options, args[3], args[4]);
    }
    else if (narg >= 4 && !strcmp(args[1], "apply"))
    {
        io_options = strchr(args[2], '?');
        if (io_options)
            *io_options++ = 0;
        retval = apply_patch(args[2], io_options, args[3]);
    }
    else
    {
        printf(
            "Patch tool for safely applying changes to block devices\n"
            "License: GNU GPLv2 or later\n"
            "Copyright (c) Vitaliy Filippov, 2014\n\n"
            "To create a backup for restoring after bad patch:\n"
            "  e2patch backup <filesystem> <patch_file> <backup_file>\n"
            "To apply a patch:\n"
            "  e2patch apply <filesystem> <patch_file>\n"
        );
        return 0;
    }
    if (retval)
    {
        com_err("e2patch", retval, _("while trying to %s"), args[1]);
    }
    return 0;
}
