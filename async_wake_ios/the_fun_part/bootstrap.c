//
//  bootstrap.c
//  async_wake_ios
//
//  Created by Viktor Oreshkin on 24.12.17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "bootstrap.h"
#include "fun_utils.h"
#include "kmem.h"
#include "patchfinder64.h"
#include "symbols.h"
#include "kcall.h"
#include "fun_objc.h"
#include <spawn.h>


int startprog(int flags, const char *prog, const char* args[], const char* envp[]) {
    pid_t pd;
    int rv = posix_spawn(&pd, prog, NULL, NULL, (char**)args, (char**)envp);

    printf("spawn '%s': pid=%d\n", prog, pd);
    printf("rv=%d\n", rv);

    if ((flags & STARTPROG_EMPOWER) && (kern_ucred == 0)) {
        int tries = 3;
        while (tries-- > 0) {
            sleep(1);
            uint64_t proc = rk64(find_allproc());
            while (proc) {
                uint32_t pid = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
                if (pid == pd) {
                    empower(proc);
                    tries = 0;
                    break;
                }
                proc = rk64(proc);
            }
        }
    }

    if (flags & STARTPROG_WAIT)
        waitpid(pd, NULL, 0);

    return rv;
}

const char *tar = "/" BOOTSTRAP_PREFIX "/tar";
static int tar_ready = 0;

int untar(const char* archive, const char *dstdir) {
    if (!tar_ready) {
        mkdir("/" BOOTSTRAP_PREFIX, 0777);
        cp(tar, resourceInBundle("tar"));
        chmod(tar, 0777);
        tar_ready = 1;
    }

    return startprog(STARTPROG_WAIT, tar, (const char*[]){ tar, "-xpf", archive, "-C", dstdir, NULL }, NULL);
}
