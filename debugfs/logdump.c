/*
 * logdump.c --- dump the contents of the journal out to a file
 * 
 * Authro: Stephen C. Tweedie, 2001  <sct@redhat.com>
 * Copyright (C) 2001 Red Hat, Inc.
 * Based on portions  Copyright (C) 1994 Theodore Ts'o.  
 *
 * This file may be redistributed under the terms of the GNU Public 
 * License.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utime.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else 
extern int optind;
extern char *optarg;
#endif
#ifdef HAVE_OPTRESET
extern int optreset;		/* defined by BSD, but not others */
#endif

#include "debugfs.h"
#include "jfs_user.h"

enum journal_location {JOURNAL_IS_INTERNAL, JOURNAL_IS_EXTERNAL};

int		dump_all, dump_contents, dump_descriptors;
unsigned int	block_to_dump, group_to_dump, bitmap_to_dump;
unsigned int	inode_block_to_dump, inode_offset_to_dump, bitmap_to_dump;
ext2_ino_t	inode_to_dump;

struct journal_source 
{
	enum journal_location where;
	int fd;
	ext2_file_t file;
};

static void dump_journal(char *, FILE *, struct journal_source *);

static void dump_descriptor_block(FILE *, struct journal_source *,
				  char *, journal_superblock_t *,
				  unsigned int *, int, tid_t);

static void dump_revoke_block(FILE *, char *, journal_superblock_t *,
				  unsigned int, int, tid_t);

static void dump_metadata_block(FILE *, struct journal_source *,
				journal_superblock_t*, 
				unsigned int, unsigned int, int, tid_t);

static void do_hexdump (FILE *, char *, int);

#define WRAP(jsb, blocknr)					\
	if (blocknr >= be32_to_cpu((jsb)->s_maxlen))		\
		blocknr -= (be32_to_cpu((jsb)->s_maxlen) -	\
			    be32_to_cpu((jsb)->s_first));


void do_logdump(int argc, char **argv)
{
	ext2_ino_t	inode;
	int		c;
	int		fd;
	int		retval;
	char		*out_fn;
	FILE		*out_file;
	
	char		*inode_spec = NULL;
	char		*journal_fn = NULL;
	int		journal_fd = 0;
	ext2_ino_t	journal_inum;
	struct ext2_inode journal_inode;
	ext2_file_t 	journal_file;
	
	char		*tmp;
	
	const char	*logdump_usage = ("Usage: logdump "
					  "[-ac] [-b<block>] [-i<inode>] "
					  "[-f<journal_file>] [output_file]");
	
	struct journal_source journal_source = {};

	optind = 0;
#ifdef HAVE_OPTRESET
	optreset = 1;		/* Makes BSD getopt happy */
#endif
	dump_all = 0;
	dump_contents = 0;
	dump_descriptors = 1;
	block_to_dump = -1;
	bitmap_to_dump = -1;
	inode_block_to_dump = -1;
	inode_to_dump = -1;
	
	while ((c = getopt (argc, argv, "ab:ci:f:")) != EOF) {
		switch (c) {
		case 'a':
			dump_all++;
			break;
		case 'b':
			block_to_dump = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				com_err(argv[0], 0,
					"Bad block number - %s", optarg);
				return;
			}
			dump_descriptors = 0;
			break;
		case 'c':
			dump_contents++;
			break;
		case 'f':
			journal_fn = optarg;
			break;
		case 'i':
			inode_spec = optarg;
			dump_descriptors = 0;
			break;
		default:
			com_err(argv[0], 0, logdump_usage);
			return;
		}
	}
	if (optind != argc && optind != argc-1) {
		com_err(argv[0], 0, logdump_usage);
		return;
	}

	if (inode_spec) {
		int inode_group, group_offset, inodes_per_block;
		
		if (check_fs_open(argv[0]))
			return;

		inode_to_dump = string_to_inode(inode_spec);
		if (!inode_to_dump)
			return;

		inode_group = ((inode_to_dump - 1)
			       / current_fs->super->s_inodes_per_group);
		group_offset = ((inode_to_dump - 1)
				% current_fs->super->s_inodes_per_group);
		inodes_per_block = (current_fs->blocksize 
				    / sizeof(struct ext2_inode));
		
		inode_block_to_dump = 
			current_fs->group_desc[inode_group].bg_inode_table + 
			(group_offset / inodes_per_block);
		inode_offset_to_dump = ((group_offset % inodes_per_block)
					* sizeof(struct ext2_inode));
		printf("Inode %u is at group %u, block %u, offset %u\n",
		       inode_to_dump, inode_group,
		       inode_block_to_dump, inode_offset_to_dump);
	}

	if (optind == argc) {
		out_file = stdout;
	} else {
		out_fn = argv[optind];
		out_file = fopen(out_fn, "w");
		if (!out_file < 0) {
			com_err(argv[0], errno, "while opening %s for logdump",
				out_fn);
			return;
		}
	}

	if (block_to_dump != -1 && current_fs != NULL) {
		group_to_dump = ((block_to_dump - 
				  current_fs->super->s_first_data_block)
				 / current_fs->super->s_blocks_per_group);
		bitmap_to_dump = current_fs->group_desc[group_to_dump].bg_block_bitmap;
	}
				 
	if (journal_fn) {

		/* Set up to read journal from a regular file somewhere */
		journal_fd = open(journal_fn, O_RDONLY, 0);
		if (journal_fd < 0) {
			com_err(argv[0], errno, "while opening %s for logdump",
				journal_fn);
			return;
		}
		
		journal_source.where = JOURNAL_IS_EXTERNAL;
		journal_source.fd = journal_fd;

	} else {

		/* Set up to read journal from the open filesystem */
		if (check_fs_open(argv[0]))
			return;
		journal_inum = current_fs->super->s_journal_inum;
		if (!journal_inum) {
			com_err(argv[0], 0, "filesystem has no journal");
			return;
		}

		retval = ext2fs_read_inode(current_fs, journal_inum, 
					   &journal_inode);
		if (retval) {
			com_err(argv[0], retval,
				"while reading inode %u", journal_inum);
			return;
		}
		
		retval = ext2fs_file_open(current_fs, journal_inum,
					  0, &journal_file);
		if (retval) {
			com_err(argv[0], retval, "while opening ext2 file");
			return;
		}
		
		journal_source.where = JOURNAL_IS_INTERNAL;
		journal_source.file = journal_file;
	}

	dump_journal(argv[0], out_file, &journal_source);

	if (journal_source.where == JOURNAL_IS_INTERNAL)
		ext2fs_file_close(journal_file);
	else
		close(journal_fd);

	if (out_file != stdout)
		fclose(out_file);

	return;
}


int read_journal_block(char *cmd, struct journal_source *source, off_t offset,
		       char *buf, int size, int *got)
{
	int retval;
	
	if (source->where == JOURNAL_IS_EXTERNAL) {
		retval = pread(source->fd, buf, size, offset);
		if (retval >= 0) {
			*got = retval;
			retval = 0;
		}
		retval = errno;
	} else {
		retval = ext2fs_file_lseek(source->file, offset, 
					   EXT2_SEEK_SET, NULL);
		if (retval) {
			com_err(cmd, retval, "while seeking in reading journal");
			return retval;
		}
		
		retval = ext2fs_file_read(source->file, buf, size, got);
	}
	
	if (retval)
		com_err(cmd, retval, "while while reading journal");
	else if (*got != size) {
		com_err(cmd, 0, "short read (read %d, expected %d) while while reading journal", *got, size);
		retval = -1;
	}
	
	return retval;
}

static char *type_to_name(int btype)
{
	switch (btype) {
	case JFS_DESCRIPTOR_BLOCK:
		return "descriptor block";
	case JFS_COMMIT_BLOCK:
		return "commit block";
	case JFS_SUPERBLOCK_V1:
		return "V1 superblock";
	case JFS_SUPERBLOCK_V2:
		return "V2 superblock";
	case JFS_REVOKE_BLOCK:
		return "revoke table";
	default:
	}
	return "unrecognised type";
}


static void dump_journal(char *cmdname, FILE *out_file, 
			 struct journal_source *source)
{
	char			jsb_buffer[1024];
	char			buf[8192];
	journal_superblock_t	*jsb;
	int			blocksize;
	int			got;
	int			retval;
	__u32			magic, sequence, blocktype;
	journal_header_t	*header;
	
	tid_t			transaction;
	unsigned int		blocknr;
	
	/* First: locate the journal superblock */

	retval = read_journal_block(cmdname, source, 0, 
				    jsb_buffer, 1024, &got);
	if (retval)
		return;
	
	jsb = (journal_superblock_t *) jsb_buffer;
	blocksize = be32_to_cpu(jsb->s_blocksize);
	transaction = be32_to_cpu(jsb->s_sequence);
	blocknr = be32_to_cpu(jsb->s_start);

	fprintf(out_file, "Journal starts at block %u, transaction %u\n",
		blocknr, transaction);

	if (!blocknr)
		/* Empty journal, nothing to do. */
		return;
		
	while (1) {
		retval = read_journal_block(cmdname, source, 
					    blocknr*blocksize, buf,
					    blocksize, &got);
		if (retval || got != blocksize)
			return;
	
		header = (journal_header_t *) buf;

		magic = be32_to_cpu(header->h_magic);
		sequence = be32_to_cpu(header->h_sequence);
		blocktype = be32_to_cpu(header->h_blocktype);
		
		if (magic != JFS_MAGIC_NUMBER) {
			fprintf (out_file, "No magic number at block %u: "
				 "end of journal.\n", blocknr);
			return;
		}
		
		if (sequence != transaction) {
			fprintf (out_file, "Found sequence %u (not %u) at "
				 "block %u: end of journal.\n", 
				 sequence, transaction, blocknr);
			return;
		}

		if (dump_descriptors) {
			fprintf (out_file, "Found expected sequence %u, "
				 "type %u (%s) at block %u\n",
				 sequence, blocktype, 
				 type_to_name(blocktype), blocknr);
		}
		
		switch (blocktype) {
		case JFS_DESCRIPTOR_BLOCK:
			dump_descriptor_block(out_file, source, buf, jsb, 
					      &blocknr, blocksize,
					      transaction);
			continue;

		case JFS_COMMIT_BLOCK:
			transaction++;
			blocknr++;
			WRAP(jsb, blocknr);
			continue;
			
		case JFS_REVOKE_BLOCK:
			dump_revoke_block(out_file, buf, jsb,
					  blocknr, blocksize, 
					  transaction);
			blocknr++;
			WRAP(jsb, blocknr);
			continue;

		default:
			fprintf (out_file, "Unexpected block type %u at "
				 "block %u.\n", blocktype, blocknr);
			return;
		}
	}
}


static void dump_descriptor_block(FILE *out_file, 
				  struct journal_source *source, 
				  char *buf,
				  journal_superblock_t *jsb, 
				  unsigned int *blockp, int blocksize,
				  tid_t transaction)
{
	int			offset;
	char			*tagp;
	journal_block_tag_t	*tag;
	unsigned int		blocknr;
	__u32			tag_block;
	__u32			tag_flags;
		

	offset = sizeof(journal_header_t);
	blocknr = *blockp;

	if (dump_all) 
		fprintf(out_file, "Dumping descriptor block, sequence %u, at "
			"block %u:\n", transaction, blocknr);
	
	++blocknr;
	WRAP(jsb, blocknr);
	
	do {
		/* Work out the location of the current tag, and skip to 
		 * the next one... */
		tagp = &buf[offset];
		tag = (journal_block_tag_t *) tagp;
		offset += sizeof(journal_block_tag_t);

		/* ... and if we have gone too far, then we've reached the
		   end of this block. */
		if (offset > blocksize)
			break;
	
		tag_block = be32_to_cpu(tag->t_blocknr);
		tag_flags = be32_to_cpu(tag->t_flags);

		if (!(tag_flags & JFS_FLAG_SAME_UUID))
			offset += 16;

		dump_metadata_block(out_file, source, jsb, 
				    blocknr, tag_block, blocksize, 
				    transaction);

		++blocknr;
		WRAP(jsb, blocknr);
		
	} while (!(tag_flags & JFS_FLAG_LAST_TAG));
	
	*blockp = blocknr;
}


static void dump_revoke_block(FILE *out_file, char *buf,
				  journal_superblock_t *jsb, 
				  unsigned int blocknr, int blocksize,
				  tid_t transaction)
{
	int			offset, max;
	journal_revoke_header_t *header;
	unsigned int		*entry, rblock;
	
	if (dump_all) 
		fprintf(out_file, "Dumping revoke block, sequence %u, at "
			"block %u:\n", transaction, blocknr);
	
	header = (journal_revoke_header_t *) buf;
	offset = sizeof(journal_revoke_header_t);
	max = be32_to_cpu(header->r_count);

	while (offset < max) {
		entry = (unsigned int *) (buf + offset);
		rblock = be32_to_cpu(*entry);
		if (dump_all || rblock == block_to_dump) {
			fprintf(out_file, "  Revoke FS block %u", rblock);
			if (dump_all)
				fprintf(out_file, "\n");
			else
				fprintf(out_file," at block %u, sequence %u\n",
					blocknr, transaction);
		}
		offset += 4;
	}
}


static void show_extent(FILE *out_file, int start_extent, int end_extent,
			__u32 first_block)
{
	if (start_extent >= 0 && first_block != 0)
		fprintf(out_file, "(%d+%u): %u ", 
			start_extent, end_extent-start_extent, first_block);
}

static void show_indirect(FILE *out_file, char *name, __u32 where)
{
	if (where)
		fprintf(out_file, "(%s): %u ", name, where);
}


static void dump_metadata_block(FILE *out_file, struct journal_source *source,
				journal_superblock_t *jsb,
				unsigned int log_blocknr, 
				unsigned int fs_blocknr, 
				int blocksize,
				tid_t transaction)
{
	int got, retval;
	char buf[8192];
	
	if (!(dump_all
	      || (fs_blocknr == block_to_dump)
	      || (fs_blocknr == inode_block_to_dump)
	      || (fs_blocknr == bitmap_to_dump)))
		return;
	
	fprintf(out_file, "  FS block %u logged at ", fs_blocknr);
	if (!dump_all) 
		fprintf(out_file, "sequence %u, ", transaction);
	fprintf(out_file, "journal block %u\n", log_blocknr);
	
	/* There are two major special cases to parse:
	 * 
	 * If this block is a block
	 * bitmap block, we need to give it special treatment so that we
	 * can log any allocates and deallocates which affect the
	 * block_to_dump query block. 
	 * 
	 * If the block is an inode block for the inode being searched
	 * for, then we need to dump the contents of that inode
	 * structure symbolically.  
	 */
	
	if (!(dump_contents && dump_all)
	    && fs_blocknr != block_to_dump
	    && fs_blocknr != bitmap_to_dump 
	    && fs_blocknr != inode_block_to_dump)
		return;
	
	retval = read_journal_block("logdump", source, 
				    blocksize * log_blocknr,
				    buf, blocksize, &got);
	if (retval)
		return;
	
	if (fs_blocknr == bitmap_to_dump) {
		struct ext2_super_block *super;
		int offset;
		
		super = current_fs->super;
		offset = ((fs_blocknr - super->s_first_data_block) %
			  super->s_blocks_per_group);
	
		fprintf(out_file, "    (block bitmap for block %u: "
			"block is %s)\n", 
			block_to_dump,
			ext2fs_test_bit(offset, buf) ? "SET" : "CLEAR");
	}
	
	if (fs_blocknr == inode_block_to_dump) {
		struct ext2_inode *inode;
		int first, prev, this, start_extent, i;
		
		fprintf(out_file, "    (inode block for inode %u):\n",
			inode_to_dump);
		
		inode = (struct ext2_inode *) (buf + inode_offset_to_dump);
		internal_dump_inode(out_file, "    ", inode_to_dump, inode, 0);
		
		/* Dump out the direct/indirect blocks here:
		 * internal_dump_inode can only dump them from the main
		 * on-disk inode, not from the journaled copy of the
		 * inode. */
		
		fprintf (out_file, "    Blocks:  ");
		start_extent = -1;

		for (i=0; i<EXT2_NDIR_BLOCKS; i++) {
			this = inode->i_block[i];
			if (start_extent >= 0  && this == prev+1) {
				prev = this;
				continue;
			} else {
				show_extent(out_file, start_extent, i, first);
				start_extent = i;
				first = prev = this;
			}
		}
		show_extent(out_file, start_extent, i, first);
		show_indirect(out_file, "IND", inode->i_block[i++]);
		show_indirect(out_file, "DIND", inode->i_block[i++]);
		show_indirect(out_file, "TIND", inode->i_block[i++]);
		
		fprintf(out_file, "\n");
	}

	if (dump_contents)
		do_hexdump(out_file, buf, blocksize);
	
}

static void do_hexdump (FILE *out_file, char *buf, int blocksize)
{
	int i,j;
	int *intp;
	char *charp;
	unsigned char c;
	
	intp = (int *) buf;
	charp = (char *) buf;
	
	for (i=0; i<blocksize; i+=16) {
		fprintf(out_file, "    %04x:  ", i);
		for (j=0; j<16; j+=4)
			fprintf(out_file, "%08x ", *intp++);
		for (j=0; j<16; j++) {
			c = *charp++;
			if (c < ' ' || c >= 127)
				c = '.';
			fprintf(out_file, "%c", c);
		}
		fprintf(out_file, "\n");
	}
}

