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

#define MAX_CSOPS_BUFFER_LEN 1024 * 1024 //based on Apple's code signing tests

static char BUFFER[MAX_CSOPS_BUFFER_LEN];
static uint32_t int_buffer;
static off_t off_buffer;
static pid_t process_id;

typedef void (^describe_t)(void);

static uint32_t bigEndianToLittleEndian(uint32_t value) {
    return ((value >> 24) & 0xff) |
           ((value << 8) & 0xff0000) |
           ((value >> 8) & 0xff00) |
           ((value << 24) & 0xff000000);
}

static struct csops_struct{
	const char* description;
	const char* command_line;
	describe_t	describe; // These are the things that make blocks shine
	unsigned int ops;
	void*	 useraddr;
	size_t	 usersize;
}

CSOPS[] = {
	/* status of current code. */
	{
		.description  = "Get the code signature status of the given PID.",
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
		.description  = "Invalidate the given PID's Code Signature.",
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
	/* set the HARD flag */
	{
		.description  = "Sets the CS_HARD (0x00000100) code signing flag on the given PID.",
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
    /* Kill the given PID if it has invalid code signature */
    {
        .description  = "Sets the CS_KILL (0x00000200) code signing flag on the given PID.",
        .command_line = "-mark_kill",
        .ops          = CS_OPS_MARKKILL,
        .useraddr      = (void*)&int_buffer,    // Unused by kernel
        .usersize      = sizeof(int_buffer),    // Unused by kernel
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Marked to be killed if "
                    "code signature invalid.\n",
                    process_id);
        }
    },
	/* the path name for executable. */
    /* This function is not supported anymore, but leaving it here */
	{
		.description  = "Get the executable path name of the PID. "
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
		.description  = "Get the code directory hash (CDHASH) of the given PID.",
		.command_line = "-cdhash",
		.ops		  = CS_OPS_CDHASH,
		.useraddr	  = (void*)BUFFER, // SHA1 of code directory
		.usersize	  = CC_SHA1_DIGEST_LENGTH,
		.describe	  = ^{
			int i;
			fprintf(stdout, "PID: %d -> Code Directory Hash: ",
					process_id);
			for(i=0;i<CC_SHA1_DIGEST_LENGTH; i++){
				fprintf(stdout, "%02x",
						(unsigned char)BUFFER[i]);
			}
			fprintf(stdout, "\n");
		}
	},
	/* Get the entitlement blob. */
	{
		.description  = "Get the entitlements blob of the given PID in XML format.",
		.command_line = "-entitlement",
		.ops		  = CS_OPS_ENTITLEMENTS_BLOB,
		.useraddr	  = (void*)BUFFER,
		.usersize	  = (MAX_CSOPS_BUFFER_LEN-1),
		.describe	  = ^{
		   fprintf(stdout,"PID: %d -> Embedded Entitlements: '%s'\n",
				process_id,
				((struct cs_blob*)BUFFER)->data);
		}

	},
	/* Get the offset of active mach-o section. */
	{
		.description  = "Get file offset of active mach-o section of the given PID.",
		.command_line = "-macho_offset",
		.ops		  = CS_OPS_PIDOFFSET,
		.useraddr	  = (void*)&off_buffer,
		.usersize	  = sizeof(off_buffer),
		.describe	  = ^{
		   fprintf(stdout, "PID: %d -> Offset of Active "
				   "Mach-O section: '0x%llx'\n",
				   process_id,
				   off_buffer);
		}
	},
    /* Get the entire CS blob. */
    {
        .description  = "Get the entire code signing blob of the given PID.",
        .command_line = "-blob",
        .ops          = CS_OPS_BLOB,
        .useraddr      = (void*)BUFFER,
        .usersize      = MAX_CSOPS_BUFFER_LEN,
        .describe      = ^{
            int i;
            uint32_t len = ((struct cs_blob*)BUFFER)->len;
            uint32_t real_length = bigEndianToLittleEndian(len);
            fprintf(stdout, "PID: %d -> Code Signing Blob: ",
                    process_id);
            for(i=0;i<real_length-8; i++){
                fprintf(stdout, "%c",
                        (unsigned char)((struct cs_blob*)BUFFER)->data[i]);
            }
            fprintf(stdout, "\n");
        }

    },
    {
        .description  = "Get the code signature identity (bundle ID) of "
        "the given PID.",
            .command_line = "-signingid",
            .ops          = CS_OPS_IDENTITY,
            .useraddr      = (void*)BUFFER,
            .usersize      = (MAX_CSOPS_BUFFER_LEN-1),
            .describe      = ^{
                fprintf(stdout,"PID: %d -> Code Signing ID: '%s'\n",
                     process_id,
                     ((struct cs_blob*)BUFFER)->data);
            }
    },
    /* mark the process as restricted. */
    {
        .description  = "Sets the CS_RESTRICT (0x00000800) code signing flag"
        "on the given PID.",
        .command_line = "-mark-restrict",
        .ops          = CS_OPS_MARKRESTRICT,
        .useraddr      = (void*)&int_buffer,    // Unused by kernel
        .usersize      = sizeof(int_buffer),    // Unused by kernel
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Marked as restricted for "
                    "code signature.\n",
                    process_id);
        }

    },
    /* Clear the installer flag */
    {
        .description  = "Clear the CS_INSTALLER (0x00000008) code signing flag "
        "on the given PID.",
        .command_line = "-clear_installer",
        .ops          = CS_OPS_CLEARINSTALLER,
        .useraddr      = (void*)&int_buffer,    // Unused by kernel
        .usersize      = sizeof(int_buffer),    // Unused by kernel
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Cleared the CS_INSTALLER flag for "
                    "code signature.\n",
                    process_id);
        }

    },
    /* Clear the platform binary flag */
    {
        .description  = "Clear the CS_PLATFORM_BINARY (0x04000000) code signing flag "
        "on the given PID.",
        .command_line = "-clear_platform",
        .ops          = CS_OPS_CLEARPLATFORM,
        .useraddr      = (void*)&int_buffer,    // Unused by kernel
        .usersize      = sizeof(int_buffer),    // Unused by kernel
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Cleared the CS_PLATFORM_BINARY flag for "
                    "code signature.\n",
                    process_id);
        }

    },
    {
        .description  = "Get the Team ID of the given PID.",
        .command_line = "-teamid",
        .ops          = CS_OPS_TEAMID,
        .useraddr      = (void*)BUFFER,
        .usersize      = (CS_MAX_TEAMID_LEN-1),
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Team ID: '%s'\n",
                    process_id,
                    ((struct cs_blob*)BUFFER)->data);
            }
    },
    /* Clear the library validation flag */
    {
        .description  = "Clear the CS_REQUIRE_LV (0x00002000) code signing flag "
        "on the given PID.",
        .command_line = "-clear_lv",
        .ops          = CS_OPS_CLEAR_LV,
        .useraddr      = (void*)&int_buffer,    // Unused by kernel
        .usersize      = sizeof(int_buffer),    // Unused by kernel
        .describe      = ^{
            fprintf(stdout, "PID: %d -> Cleared the CS_REQUIRE_LV flag for "
                    "code signature.\n",
                    process_id);
        }

    },
    /* Get the DER entitlement blob. */
    {
        .description  = "Get the entitlements blob in DER format "
        "of the given PID.",
        .command_line = "-der_entitlement",
        .ops          = CS_OPS_DER_ENTITLEMENTS_BLOB,
        .useraddr      = (void*)BUFFER,
        .usersize      = (MAX_CSOPS_BUFFER_LEN-1),
        .describe      = ^{
           fprintf(stdout,"PID: %d -> Embedded Entitlements (DER): '%s'\n",
                process_id,
                ((struct cs_blob*)BUFFER)->data);
        }

    },
    /* Get the validation category. */
    {
        .description  = "Get the validation category of the given PID.",
        .command_line = "-validation_category",
        .ops          = CS_OPS_VALIDATION_CATEGORY,
        .useraddr      = (void*)&off_buffer,
        .usersize      = sizeof(off_buffer),
        .describe      = ^{
           fprintf(stdout, "PID: %d -> Validation category: "
                   "'%llu'\n",
                   process_id,
                   off_buffer);
        }
    },
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

	if (process_id < 0 || process_id > 99999) {
		fprintf(stderr, "Invalid process id: %s\n", argv[argc-1]);
		usage(argc, argv);
		return -1;
	}

	for (i=1; i<argc-1; i++) {
		exec_csops(argv[i]);
	}

	return 0;
}
