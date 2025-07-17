/*
 * Create: Thu Jul 17 05:47:29 2025
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>

int main() {

    if (unshare(CLONE_NEWUSER) == -1) {
        perror("unshare(CLONE_NEWUSER) failed");
        return 1;
    }

    const char *mount_path = "/sys/fs/bpf/token3";
    if (mount("bpffs", mount_path, "bpf", 0, "delegate_cmds=prog_load") == -1) {
        perror("mount bpffs failed");
        return 1;
    }

    printf("BPF filesystem mounted at %s\n", mount_path);
    sleep(100000);
    return 0;
}

