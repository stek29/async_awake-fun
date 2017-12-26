//
//  procfinder.h
//  async_wake_ios
//
//  Created by Viktor Oreshkin on 25.12.17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef procfinder_h
#define procfinder_h

#include <inttypes.h>

int enumerate_tasks(int (*f)(uint64_t, void* data), void* data);
uint64_t kerntask_for_pid(uint32_t pid);
uint64_t proc_for_task(uint64_t kerntask);

#endif /* procfinder_h */
