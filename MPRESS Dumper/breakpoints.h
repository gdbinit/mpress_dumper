/*
 * ._____.___ ._______ .______  ._______.________.________
 * :         |: ____  |: __   \ : .____/|    ___/|    ___/
 * |   \  /  ||    :  ||  \____|| : _/\ |___    \|___    \
 * |   |\/   ||   |___||   :  \ |   /  \|       /|       /
 * |___| |   ||___|    |   |___\|_.: __/|__:___/ |__:___/
 * |___|         |___|       :/      :        :
 *
 * .______  .____     ._____.___ ._______ ._______.______
 * :_ _   \ |    |___ :         |: ____  |: .____/: __   \
 * |   |   ||    |   ||   \  /  ||    :  || : _/\ |  \____|
 * | . |   ||    :   ||   |\/   ||   |___||   /  \|   :  \
 * |. ____/ |        ||___| |   ||___|    |_.: __/|   |___\
 * :/      |. _____/       |___|            :/   |___|
 * :        :/
 *          :
 *
 * MPRESS Packer dumper
 *
 * Created by Pedro Vilaca on 26/01/14.
 * Copyright (c) 2014 Pedro Vilaca. All rights reserved.
 * http://reverse.put.as - reverser@put.as
 *
 * breakpoints.h
 *
 */


#ifndef MPRESS_Dumper_breakpoints_h
#define MPRESS_Dumper_breakpoints_h

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include "uthash.h"
#include "utlist.h"

/*
 * software breakpoints are independent of threads
 * we have a function pointer that indicates which function will process the exception
 * this is an additional argument to insert_breakpoint()
 */
struct soft_bp
{
	mach_vm_address_t address;     // the hash table key
    uint32_t size;
	uint8_t type;
	vm_offset_t originalopcode;
	vm_prot_t originalprotection;  // original memory protection
	kern_return_t (*exception_processor)(mach_port_t, int *, thread_state_t, thread_state_t);
    char *name;                    // exception processor name
    struct soft_bp *next;
};

kern_return_t insert_breakpoint(mach_port_t task, mach_vm_address_t address, void* exception_processor, char *processor_name);
kern_return_t delete_breakpoint(mach_port_t task, mach_vm_address_t address);
kern_return_t delete_all_breakpoints(mach_port_t task);

#endif
