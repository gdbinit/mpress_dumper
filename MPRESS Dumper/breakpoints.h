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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
