// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/bpf.h>
#include <linux/const.h>

#include "json_writer.h"
#include "main.h"

#define MAX_LINE_LEN 1024
#define MOUNTS_FILE "/proc/mounts"
#define MAX_BPF_MOUNT_POINGT_CNT 32

#define zclose(fd) do { if (fd >= 0) close(fd); fd = -1; } while (0)
#define BIT_ULL(nr) (ULL(1) << (nr))

static const char *cmd_type_name[] = {
	[BPF_MAP_CREATE]		= "map_create",
	[BPF_MAP_LOOKUP_ELEM]		= "map_lookup_elem",
	[BPF_MAP_UPDATE_ELEM]		= "map_update_elem",
	[BPF_MAP_DELETE_ELEM]		= "map_delete_elem",
	[BPF_MAP_GET_NEXT_KEY]		= "map_get_next_key",
	[BPF_PROG_LOAD]			= "prog_load",
	[BPF_OBJ_PIN]			= "obj_pin",
	[BPF_OBJ_GET]			= "obj_get",
	[BPF_PROG_ATTACH]		= "prog_attach",
	[BPF_PROG_DETACH]		= "prog_detach",
	[BPF_PROG_RUN]			= "prog_run",
	[BPF_PROG_GET_NEXT_ID]		= "prog_get_next_id",
	[BPF_MAP_GET_NEXT_ID]		= "map_get_next_id",
	[BPF_PROG_GET_FD_BY_ID]		= "prog_get_fd_by_id",
	[BPF_MAP_GET_FD_BY_ID]		= "map_get_fd_by_id",
	[BPF_OBJ_GET_INFO_BY_FD]	= "obj_get_info_by_fd",
	[BPF_PROG_QUERY]		= "prog_query",
	[BPF_RAW_TRACEPOINT_OPEN]	= "raw_tracepoint_open",
	[BPF_BTF_LOAD]			= "btf_load",
	[BPF_BTF_GET_FD_BY_ID]		= "btf_get_fd_by_id",
	[BPF_TASK_FD_QUERY]		= "task_fd_query",
	[BPF_MAP_LOOKUP_AND_DELETE_ELEM] = "map_lookup_and_delete_elem",
	[BPF_MAP_FREEZE]		= "map_freeze",
	[BPF_BTF_GET_NEXT_ID]		= "btf_get_next_id",
	[BPF_MAP_LOOKUP_BATCH]		= "map_lookup_batch",
	[BPF_MAP_LOOKUP_AND_DELETE_BATCH] = "map_lookup_and_delete_batch",
	[BPF_MAP_UPDATE_BATCH]		= "map_update_batch",
	[BPF_MAP_DELETE_BATCH]		= "map_delete_batch",
	[BPF_LINK_CREATE]		= "link_create",
	[BPF_LINK_UPDATE]		= "link_update",
	[BPF_LINK_GET_FD_BY_ID]		= "link_get_fd_by_id",
	[BPF_LINK_GET_NEXT_ID]		= "link_get_next_id",
	[BPF_ENABLE_STATS]		= "enable_stats",
	[BPF_LINK_DETACH]		= "link_detach",
	[BPF_PROG_BIND_MAP]		= "prog_bind_map",
	[BPF_TOKEN_CREATE]		= "token_create",
	[BPF_PROG_STREAM_READ_BY_FD]	= "prog_stream_read_by_fd",
	[__MAX_BPF_CMD]			= "invalid",
};

static bool is_init_user_ns() {
	struct stat self_st, init_st;

	stat("/proc/self/ns/user", &self_st);
	stat("/proc/1/ns/user", &init_st);

	return self_st.st_ino == init_st.st_ino;
}

static const char *bpf_cmd_type_str(enum bpf_cmd t)
{
	if (t < 0 || t >= ARRAY_SIZE(cmd_type_name))
		return NULL;

	return cmd_type_name[t];
}

static bool has_delegate_options(const char *mnt_ops) {
	return (strstr(mnt_ops, "delegate_cmds") != NULL ||
		strstr(mnt_ops, "delegate_maps") != NULL ||
		strstr(mnt_ops, "delegate_progs") != NULL ||
		strstr(mnt_ops, "delegate_attachs") != NULL);
}

static int parse_bpf_mounts(char **mount_point, int *cnt, int max_cnt)
{
	FILE *fp;
	struct mntent *ent;
	int id = 0;

	fp = setmntent(MOUNTS_FILE, "r");
	if (!fp) {
		p_err("Failed to open:%s", MOUNTS_FILE);
		return -1;
	}

	while ((ent = getmntent(fp)) != NULL) {
		if (strcmp(ent->mnt_type, "bpf") == 0) {
			if (has_delegate_options(ent->mnt_opts) && id < max_cnt) {
				mount_point[id] = strdup(ent->mnt_dir);
				if (!mount_point[id])
					return -ENOMEM;
				id++;
			}
		}
	}
	
	*cnt = id > max_cnt ? max_cnt : id;

	return 0;
}

#define ITEMS_PER_LINE 4

#define PRINT_ALLOWED_BPF_TYPES(max_type, allowed_type, type_str_fn)			\
do {											\
	mask = BIT_ULL((max_type)) - 1;							\
	if (((allowed_type) & mask) == mask)						\
		printf("\n\tany");							\
	else {										\
		for (int i = 0; i < (max_type); i += ITEMS_PER_LINE) {			\
			if ((allowed_type) & BIT_ULL(i)) {				\
				buf[id] = (char *)type_str_fn(i);			\
				id++;							\
			}								\
			if ((id == ITEMS_PER_LINE) ||					\
			    (id > 0 && (i + ITEMS_PER_LINE > __MAX_BPF_PROG_TYPE))) {	\
				printf("\n\t%-20s %-20s %-20s %-20s",			\
				       buf[0], buf[1], buf[2], buf[3]);			\
				id = 0;							\
				memset(buf, 0, sizeof(buf));				\
			}								\
		}									\
	}										\
} while (0)

static int show_token_info_plain(struct bpf_token_info *info,
				 const char *mount_point)
{

	char* buf[ITEMS_PER_LINE];
	int id = 0;
	__u64 mask;

	memset(buf, 0, sizeof(buf));

	printf("\n\ttoken_info: %s", mount_point);
	printf("\n\tallowed_cmds:");
	PRINT_ALLOWED_BPF_TYPES(__MAX_BPF_CMD, info->allowed_cmds, bpf_cmd_type_str);

	printf("\n\tallowed_maps:");
	PRINT_ALLOWED_BPF_TYPES(__MAX_BPF_MAP_TYPE, info->allowed_maps,
				libbpf_bpf_map_type_str);
#if 0
	for (int i = 0; i < __MAX_BPF_MAP_TYPE; i + ITEMS_PER_LINE) {
		if (info->allowed_maps & BIT_ULL(i)) {
			buf[id] = libbpf_bpf_map_type_str(i);
			id++;
		}
		if ((id == ITEMS_PER_LINE) ||
		    (id > 0 && (i + ITEMS_PER_LINE > __MAX_BPF_PROG_TYPE))) {
			printf("\n\t%-20s %-20s %-20s %-20s",
			       buf[0], buf[1], buf[2], buf[3]);
			id = 0;
			memset(buf, 0, sizeof(buf));
		}
	}
#endif

	printf("\n\tallowed_progs:");
	PRINT_ALLOWED_BPF_TYPES(__MAX_BPF_PROG_TYPE, info->allowed_progs,
				libbpf_bpf_prog_type_str);

	printf("\n\tallowed_attachs:");
	PRINT_ALLOWED_BPF_TYPES(__MAX_BPF_ATTACH_TYPE, info->allowed_attachs,
				libbpf_bpf_attach_type_str);

	return 0;
}

static int show_token_info_json(struct bpf_token_info *info,
				const char *mount_point, json_writer_t *wtr)
{
	return 0;
}

static int show_token_info(const char *point)
{
	int err = 0, bpffs_fd = -1, token_fd = -1;
	struct bpf_token_info info;
	__u32 len = sizeof(struct bpf_token_info);

	if (is_init_user_ns()) {
		p_err("Creating BPF token in init_user_ns not supported yet!");
		return -EOPNOTSUPP;
	}

	bpffs_fd = open(point, 0, O_RDWR);
	if (bpffs_fd < 0) {
		p_err("Failed to open:%s\n, err:%s", point, strerror(errno));
		err = -errno;
		return err;
	}

	token_fd = bpf_token_create(bpffs_fd, NULL);
	if (token_fd < 0) {
		p_err("Failed to create token, err:%s", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	memset(&info, 0, len);
	err = bpf_obj_get_info_by_fd(token_fd, &info, &len);
	if (err) {
		p_err("Failed to get token info, err:%s", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	show_token_info_plain(&info, point);

	//TODO
	show_token_info_json(&info, point, NULL);
cleanup:
	zclose(bpffs_fd);
	zclose(token_fd);

	return err;
}

static int do_show(int argc, char **argv)
{
	int err, cnt = 0;
	char **mount_point;

	mount_point = calloc(MAX_BPF_MOUNT_POINGT_CNT, sizeof(char *));
	if (!mount_point) {
		p_err("mem alloc failed");
		return -ENOMEM;
	}
	err = parse_bpf_mounts(mount_point, &cnt, MAX_BPF_MOUNT_POINGT_CNT);
	if (err)
		goto cleanup;

	for (int i = 0; i < cnt; i++) {
		err = show_token_info(mount_point[i]);
		if (err)
			break;
	}

cleanup:
	for(int i = 0; i < cnt; i++) {
		if (mount_point[i])
			free(mount_point[i]);
	}

	return 0;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }\n"
		"	%1$s %2$s help\n"
		"\n"
		"",
		bin_name, argv[-2]);
	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "help",	do_help },
	{ "list",	do_show },
	{ 0 }
};

int do_token(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
