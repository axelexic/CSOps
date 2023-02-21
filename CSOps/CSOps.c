//
//  CSOps.c
//  CSOps

/**
* Copyright (C) 2012 Yogesh Prem Swami. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/


#include <unistd.h>		// getpid()
#include <stdio.h>		// printf() etc
#include <stdlib.h>		// atoi()
#include <string.h>		// strlen()
#include <errno.h>		// strerror()
#include <ctype.h>
#include "codesign.h"		// csops() and additional flags
#include <sys/syslimits.h>	// PATH_MAX
#include <CommonCrypto/CommonDigest.h>	// SHA_HASH_LENGTH. Gratutous? Yes!

#define MAX_CSOPS_BUFFER_LEN 3*PATH_MAX	 // 3K < 1 page

static char BUFFER[MAX_CSOPS_BUFFER_LEN];
static uint32_t int_buffer;
static off_t		  off_buffer;
static pid_t process_id;

typedef void (^describe_t)(void);


static struct csops_struct{
	const char* description;
	const char* command_line;
	describe_t	describe; // These are the things that make blocks shine
	unsigned int ops;
	void*	 useraddr;
	size_t	 usersize;
}CSOPS[] = {
	/* status of current code. */
	{
		.description  = "Return the code signature status of "
			         "the given PID.",
		.command_line = "-status",
		.ops		  = CS_OPS_STATUS,
		.useraddr	  = (void*)&int_buffer,
		.usersize	  = sizeof(int_buffer),

		/*
		 * In theory one can put csops system call in the
		 * block itself, but that would create a lot of
		 * duplicate code. So it's better to handle
		 * it separately.
		 */

		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Code Signing Status: %x\n",
					process_id, int_buffer);
		}
	},
	/* Mark the process as a invalid. */
	{
		.description  = "Mark a given PID as having invalid Code Signature.",
		.command_line = "-mark_invalid",
		.ops		  = CS_OPS_MARKINVALID,
		.useraddr	  = (void*)&int_buffer,	// Unused by kernel
		.usersize	  = sizeof(int_buffer),  // Unused by kernel
		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Marked to have invalid "
				"code signature\n",
				process_id);
		}
	},
	/* kill the process if it's invalid. */
	{
		.description  = "Kill the given PID if it has invalid "
				"code signature.",
		.command_line = "-kill_if_invalid",
		.ops		  = CS_OPS_MARKKILL,
		.useraddr	  = (void*)&int_buffer,	// Unused by kernel
		.usersize	  = sizeof(int_buffer),	// Unused by kernel
		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Marked to be killed if "
					"code signature invalid.\n",
					process_id);
		}
	},
	/* mark the process as hard. Not sure what it means! */
	{
		.description  = "Doesn't seem to do anything useful... :-)",
		.command_line = "-mark_hard",
		.ops		  = CS_OPS_MARKHARD,
		.useraddr	  = (void*)&int_buffer,	// Unused by kernel
		.usersize	  = sizeof(int_buffer),	// Unused by kernel
		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Marked as hard for "
					"code signature.\n",
					process_id);
		}

	},
	/* the path name for executable. */
	{
		.description  = "Return the executable path name for PID. "
				"Used by taskgated.",
		.command_line = "-executable_path",
		.ops		  = CS_OPS_PIDPATH,
		.useraddr	  = (void*)BUFFER,  // Path for PID returned
		.usersize	  = (PATH_MAX-1),
		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Executable path: '%s'\n",
					process_id,
					BUFFER);
		}
	},
	/* Get the hash of code directory. */
	{
		.description  = "Return the Hash of the code directory.",
		.command_line = "-code_directory_hash",
		.ops		  = CS_OPS_CDHASH,
		.useraddr	  = (void*)BUFFER, // SHA1 of code directory
		.usersize	  = CC_SHA1_DIGEST_LENGTH,
		.describe	  = ^{
			int i;
			fprintf(stdout, "PID: %d -> Code Directory hash: ",
					process_id);
			for(i=0;i<CC_SHA1_DIGEST_LENGTH-1; i++){
				fprintf(stdout, "%02x:",
						(unsigned char)BUFFER[i]);
			}
			fprintf(stdout, "%02x\n",
			     (unsigned char)BUFFER[CC_SHA1_DIGEST_LENGTH-1]);
		}
	},
	/* Get the entitlement blob. */
	{
		.description  = "Return the entitlements blob.",
		.command_line = "-entitlement",
		.ops		  = CS_OPS_ENTITLEMENTS_BLOB,
		.useraddr	  = (void*)BUFFER,
		.usersize	  = (MAX_CSOPS_BUFFER_LEN-1),
		.describe	  = ^{
		   fprintf(stdout,"PID: %d -> Embedded Entitlements: '%s'\n",
				process_id,
				BUFFER);
		}

	},
	/* Get the offset of active mach-o section. */
	{
		.description  = "Return file offset of active mach-o section.",
		.command_line = "-macho_offset",
		.ops		  = CS_OPS_PIDOFFSET,
		.useraddr	  = (void*)&off_buffer,
		.usersize	  = sizeof(off_buffer),
		.describe	  = ^{
		   fprintf(stdout, "PID: %d -> Offset of Active "
				   "Mach-O section: '%llu'\n",
				   process_id,
				   off_buffer);
		}
	},
	/* Mark the process as restricted. */
	{
		.description  = "Mark the process as sandboxed. "
				"Enforced on all future child processes.",
		.command_line = "-restrict",
		.ops		  = CS_OPS_STATUS,
		.useraddr	  = (void*)&int_buffer,	// Unused by kernel
		.usersize	  = sizeof(int_buffer),	// Unused by kernel
		.describe	  = ^{
			fprintf(stdout, "PID: %d -> Marked as restricted "
					"(sandboxed).\n", process_id);
		}
	},
    {
        .description  = "Return the code signature identity of "
        "the given PID.",
            .command_line = "-signingid",
            .ops          = CS_OPS_IDENTITY,
            .useraddr      = (void*)BUFFER,
            .usersize      = (sizeof(BUFFER)-1),

        /*
         * In theory one can put csops system call in the
         * block itself, but that would create a lot of
         * duplicate code. So it's better to handle
         * it separately.
         */

            .describe      = ^{
                int i;
                fprintf(stdout, "PID: %d -> Code Singing ID: ",
                        process_id);
                for(i=0;i<sizeof(BUFFER)-1; i++) {
                    if (isprint(BUFFER[i])) {
                        fprintf(stdout, "%c", (unsigned char)BUFFER[i]);
                    }
                }
                fprintf(stdout, "\n");
            }
    }
};


#define CSOPS_SIZE (sizeof(CSOPS)/sizeof(CSOPS[0]))


static int exec_csops(const char* const cmd){
	int i;
	int result;
	struct csops_struct* cs;

	if (cmd == NULL) {
		return -1;
	}

	for (i=0; (i< CSOPS_SIZE) ; i++){
		if (strcmp(cmd, CSOPS[i].command_line) == 0) {
			cs = &CSOPS[i];
			break;
		}
	}

	if (i == CSOPS_SIZE) {
		return -1;
	}

	result = csops(process_id, cs->ops, cs->useraddr, cs->usersize);

	if (result < 0) {
		fprintf(stderr, "csops(%s) failed: %s\n", cmd, strerror(errno));
		return -1;
	}else{
		cs->describe();
	}

	return 0;
}

static void usage(int argc, const char* const argvp[]){
	int i;
	long long fill_space=0;
	long long string_width_max = 25;

	fprintf(stderr, "Usage: %s [options] PID\nOptions are:\n", argvp[0]);

	for (i=0; i<CSOPS_SIZE; i++) {
		fprintf(stderr, "\t%s", CSOPS[i].command_line);
		fill_space = string_width_max - strlen(CSOPS[i].command_line);
		while (fill_space-- > 0) fprintf(stderr, " ");
		fprintf(stderr, ": %s\n", CSOPS[i].description);
	}
}


int main (int argc, const char * argv[])
{
	int i;

	if (argc < 2) {
		usage(argc, argv);
		return -1;
	}

	/* The last argument is the process ID. */
	process_id = atoi(argv[argc-1]);

	if (process_id < 0 ) {
		fprintf(stderr, "Invalid process id: %s\n", argv[argc-1]);
		usage(argc, argv);
		return -1;
	}

	for (i=1; i<argc-1; i++) {
		exec_csops(argv[i]);
	}

	return 0;
}
