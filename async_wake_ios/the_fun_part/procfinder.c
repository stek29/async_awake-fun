//
//  procfinder.c
//  async_wake_ios
//
//  Created by Viktor Oreshkin on 25.12.17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "procfinder.h"
#include "kmem.h"
#include "symbols.h"
#include "kutils.h"

int enumerate_tasks(int (*f)(uint64_t, void* data), void* data) {
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t next_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));

    while ((struct_task & 0xfffff00000000000) != 0) {
        if (f(struct_task, data) != 0) return 0;
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }

    struct_task = next_task;
    while ((struct_task & 0xfffff00000000000) != 0) {
        if (f(struct_task, data) != 0) return 0;
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_NEXT));
    }

    return -1;
}

struct kerntask_for_pid_data {
    uint64_t found_task;
    pid_t pid;
};

static int kerntask_for_pid_inner(uint64_t struct_task, void* vdata) {
    struct kerntask_for_pid_data *data = (struct kerntask_for_pid_data *) vdata;

    uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    if (bsd_info == 0) return 0;

    uint32_t found_pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
    if (found_pid == data->pid) {
        data->found_task = struct_task;
        return 1;
    } else {
        return 0;
    }
}

uint64_t kerntask_for_pid(uint32_t pid) {
    struct kerntask_for_pid_data pid_data = {0, pid};

    if (enumerate_tasks(kerntask_for_pid_inner, &pid_data) == 0) {
        return pid_data.found_task;
    }

    return -1;
}

uint64_t proc_for_task(uint64_t kerntask) {
    if (kerntask != -1) {
        uint64_t ret = rk64(kerntask + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        if ((ret & 0xfffff00000000000) != 0) return ret;
    }
    return -1;
}
