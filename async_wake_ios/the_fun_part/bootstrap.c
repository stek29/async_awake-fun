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


uint64_t pid2proc(pid_t pid, int tries) {
    while (tries-- > 0) {
        sleep(1);
        uint64_t proc = rk64(find_allproc());
        while (proc) {
            uint32_t pd = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
            if (pd == pid) {
                return proc;
            }
            proc = rk64(proc);
        }
    }
    return 0;
}

int startprog(int flags, const char *prog, const char* args[], const char* envp[]) {
    pid_t pd;
    int rv = posix_spawn(&pd, prog, NULL, NULL, (char**)args, (char**)envp);

    printf("spawn '%s': pid=%d\n", prog, pd);
    printf("posix_spawn: =%d (%s)\n", rv, (rv == 0)?"success":strerror(rv));

    if (rv != 0) {
        return rv;
    }

    if ((flags & STARTPROG_EMPOWER) && (kern_ucred != 0)) {
        uint64_t proc = pid2proc(pd, 3);
        if (proc != 0) {
            printf("pid2proc failed for pid=%u\n", pd);
        } else {
            empower(proc);
        }
    }

    if (flags & STARTPROG_WAIT) {
        // why does it always return -1?!
        int wpv = waitpid(pd, &rv, 0);
        printf("waitpid: =%d\n", wpv);
        if (wpv == -1) {;
            rv = wpv;
        } else {
            printf("exit code: =%d\n", rv);
        }
    }

    return rv;
}

void doubleforkexec(const char *prog, const char* args[], const char* envp[]);

const char *tar = "/" BOOTSTRAP_PREFIX "/tar";
static int tar_ready = 0;

int untar(const char* archive, const char *dstdir) {
    if (!tar_ready) {
        printf("mkdir: %d\n", mkdir("/" BOOTSTRAP_PREFIX, 777));
        printf("unlink: %d\n", unlink(tar));
        printf("cp: %d\n", cp(resourceInBundle("tar"), tar));
        printf("chmod: %d\n", chmod(tar, 777));
        tar_ready = 1;
    }

//    return startprog(STARTPROG_EMPOWER|STARTPROG_WAIT,
//                     tar,
//                     (const char*[]){ tar, "-xvpf", archive, "-C", dstdir, NULL },
//                     NULL);


    doubleforkexec(tar, (const char*[]){ tar, "--help", NULL}, NULL);

    return 1337;
}

void doubleforkexec(const char *prog, const char* args[], const char* envp[]) {
    // "only launchd is allowed to spawn untrusted binaries" is raised in
    // sandbox's mpo_cred_label_update_execve hook
    // it's caused if amfi_copy_seatbelt_profile_names "fails", or if all of following is true:
    //  - exec'd binary lacks seatbelt-profiles entilement
    //  - exec'd binary doesn't have platform-application=true entitlement
    //  - proc_ppid() isn't 1
    // When I was talking to Siguza about it he has suggested to
    // double fork, kill first fork (so second fork has ppid=1), and do exec.
    // That made the last check pass :)

    // However, process is still being killed -- now because "outside of container && !i_can_has_debugger"
    // And kernel panic happens :(

    // So, the best solution for now is just adding platform-application = true
    // entitlement to everything you want to execute

    // I wonder how J/Morpheus got around this...
    // Btw, why the hell does it work for binaries which are injected into trust cache?!

    // -------------------------

    // Initially I wanted to pass (pid1 - pid2) as exit code of child
    // So parent knew difference between child and grandchild pids
    // However, it didn't work. Then I tried posix shared memory for fun and failed.
    // So I ended up implying that the difference is 1

    pid_t pid1 = fork();

    if (pid1 != 0) {
        // still parent process

        // empower child & for it to exit
        empower(pid2proc(pid1, 3));
        int status = 0;
        waitpid(pid1, &status, 0);

        // empower grandchild
        printf("Child exit status is %d\n", status);
        printf("Implying grandchild pid is %u\n", pid1 + 1);
        empower(pid2proc(pid1 + 1, 3));
    } else {
        // child process
        sleep(4); // wait for empower
        setuid(0);
        pid_t pid2 = fork();
        if (pid2 != 0) {
            // still child
            printf("Grandchild pid is %u\n", pid2);
            exit(0);
        } else if (!pid2) {
            // grandchild
            sleep(4); // wait for empower
            setuid(0);

            execve(prog, (char**)args, (char**)envp);
        }
    }
}
