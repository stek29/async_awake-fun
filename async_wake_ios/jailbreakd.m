//
//  jailbreakd.m
//  topanga
//
//  Created by Abraham Masri on 12/17/17.
//  Copyright © 2017 Abraham Masri. All rights reserved.
//

#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>

#include "procfinder.h"
#include "kutils.h"
#include "kcall.h"
#include "symbols.h"
#include "kmem.h"

#include <errno.h>
#include <dirent.h>

NSMutableArray *processed_procs;
uint64_t task_self;


#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */

uint32_t ourpid;

int empowerX(uint64_t forward_struct_task, void* data) {
    NSMutableArray* procs = (__bridge NSMutableArray*) data;
    uint64_t bsd_info = rk64(forward_struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));

    // check if we already processed this proc
    if(![procs containsObject:@(bsd_info)]) {
        uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        char p_comm[18];
        rkbuffer(bsd_info + 0x268 /*p_comm*/, &p_comm, 16);
        p_comm[16] = '\0';

//        if (pid > ourpid) {
        if (strstr(p_comm, "cydo") || strstr(p_comm, "runAsSuperuser")) {
            uint32_t csflags = rk32(bsd_info  + 0x2a8 /* csflags */);
            csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_KILL | CS_HARD);
            wk32(bsd_info + 0x2a8 /* csflags */, csflags);
            printf("[INFO]: processed pid: %d\n", pid);
        }

        [procs addObject:@(bsd_info)];
    }

    return 0;
}

/*
 *  Purpose: scans for new procs (all procs AFTER ours)
 */
void *start_scanning() {
    ourpid = getpid();
    if(processed_procs == nil)
        processed_procs = [[NSMutableArray alloc] init];

    // uh..
    while(1) {
        enumerate_tasks(empowerX,  (__bridge void*) processed_procs);
    }
}

/*
 *  Purpose: Any initialization required is done here
 */
void start_jailbreakd(void) {

    task_self = task_self_addr();

    printf("[*]: welcome to jailbreakd\n");
    sleep(1);

    printf("[INFO]: scanning for new procs in a separate thread\n");
//    start_scanning();
    pthread_t tid;
//    pthread_create(&tid, NULL, start_scanning, NULL);
    printf("[INFO]: scanner is running!\n");
}
