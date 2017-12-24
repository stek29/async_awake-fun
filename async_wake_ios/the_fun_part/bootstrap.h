//
//  bootstrap.h
//  async_wake_ios
//
//  Created by Viktor Oreshkin on 24.12.17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef bootstrap_h
#define bootstrap_h

#include <inttypes.h>

#define BOOTSTRAP_PREFIX "bootstrap"

enum STARTPROG_FLAGS {
    STARTPROG_NONE     = 0,
    STARTPROG_WAIT     = 1,
    STARTPROG_EMPOWER  = 2,
};

int startprog(int flags, const char *prog, const char* args[], const char* envp[]);
int untar(const char* archive, const char *dstdir);

#endif /* bootstrap_h */
