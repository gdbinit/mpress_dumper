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
 * dumper.c
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

#import <Cocoa/Cocoa.h>
#import "mdumperAppDelegate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <signal.h>
#include <mach-o/loader.h>

#include "dumper.h"
#include "breakpoints.h"
#include <capstone.h>

// arch of the target to be dumped
uint32 targetMagic = 0;
// the port for our target task
mach_port_t g_targetTask = -1;
// exception handling
mach_port_t g_exceptionPort;
extern struct soft_bp *g_breakpoints;

mach_vm_address_t g_unpacking_addr = 0;
uint64_t g_unpacking_size = 0;
static int l_dumping_finished = 0;

static const char *targetFile = NULL;

// exception message we will receive from the kernel
// these structures must be different based on the type of exception we want
// check mach_excServer.c for their definition for each type
typedef struct exc_msg {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[224];
} exc_msg_t;

// reply message we will send to the kernel
typedef struct rep_msg {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[224];
} reply_msg_t;

extern boolean_t mach_exc_server(mach_msg_header_t *request,mach_msg_header_t *reply);

/* local functions */
static void install_debugger(int pid);
static void debug_loop(void);
static kern_return_t find_unpack_addresses(mach_vm_address_t start_addr, mach_vm_address_t end_addr, mach_vm_address_t *first_bp, mach_vm_address_t *second_bp);
static kern_return_t process_firstbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state);
static kern_return_t process_secondbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state);
static kern_return_t process_thirdbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state);
static kern_return_t process_oepbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state);
static kern_return_t find_secondstage_entrypoint(mach_vm_address_t start, mach_vm_address_t *out_ep);
static kern_return_t find_oep(mach_vm_address_t start_addr, mach_vm_address_t *oep_bp);
static kern_return_t process_and_dump_to_disk(void);

#pragma mark -
#pragma mark Where the unpacking starts

int
unpack_mpress(const char *sourcePath, const char *targetPath, mach_vm_address_t entrypoint, mach_vm_address_t end_addr)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    if (getuid() == 0)
	{
		NSLog(@"[ERROR] Please do not run me as root, it will not work! Fix permissions to procmod or add necessary entitlements/code signing.");
		exit(-1);
	}
    
    // we launch the command using arch for the 32bits targets
	char *cmd[] = { (char*)sourcePath, (char *)0 };
    
    pid_t pid = vfork();
	int error = 0;
	// DON'T FORGET TO DROP PRIVILEGES HERE!
	if (pid == 0)
	{ // child
		// drop privileges
		setuid(getuid());
		setgid(getgid());
		errno = 0;
		// the new process will start in a suspended state
        // XXX: this should use posix_spawn instead and disable ASLR (although MPRESS isn't ASLR compatible!)
		error = ptrace(PT_TRACE_ME, 0, 0, 0);
		if (errno)
		{
			NSLog(@"[ERROR] PT_TRACE_ME Errno: %s\n", strerror(errno));
			exit(1);
		}
        
#if DEBUG
		NSLog(@"[DEBUG] execvin'g %s...\n", sourcePath);
#endif
		// run the target
		execv(sourcePath, cmd);
		NSLog(@"[ERROR] Failed to execv!");
		exit(1);
	}
	else if (pid < 0)
	{ // something went bad!
		NSLog(@"[ERROR] vfork failed!");
	}
	else
	{ // parent
        int status = 0;
		/* wait for the child */
		waitpid(pid, &status,0);
		errno = 0;
        targetFile = targetPath;
        /* now we can install the debugger */
        install_debugger(pid);
        /* find initial addresses and insert breakpoints */
        mach_vm_address_t first_bp = 0;
        mach_vm_address_t second_bp = 0;
        if (find_unpack_addresses(entrypoint, end_addr, &first_bp, &second_bp) != KERN_SUCCESS)
        {
            NSLog(@"[ERROR] Failed to find initial addresses!");
            /* kill the process */
            kill(pid, SIGKILL);
        }
        insert_breakpoint(g_targetTask, first_bp, process_firstbreakpoint, "aaa");
        insert_breakpoint(g_targetTask, second_bp, process_secondbreakpoint, "bbb");
        /* and now we can continue the process
		 * we can detach from the process since we don't need ptrace anymore...
         */
		if ( ptrace(PT_DETACH, pid, 0, 0) )
		{
			NSLog(@"[ERROR] PT_CONTINUE Errno: %s\n", strerror(errno));
            /* kill the process */
            kill(pid, SIGKILL);
			return -1;
		}
    }
    
    /* XXX: ugly way to wait for unpacking to finish :X */
    struct timespec wait_time = {0};
    wait_time.tv_nsec = 40000000;
    
    while (l_dumping_finished == 0)
    {
        nanosleep(&wait_time, NULL);
    }
    l_dumping_finished = 0;
    
    if (g_exceptionPort)
    {
        mach_port_deallocate(mach_task_self(), g_exceptionPort);
	}
    
    return 0;
}

#pragma mark -
#pragma mark Functions to find addresses

/* 
 * find the initial breakpoint addresses to help find the second stage decryption stub
 * we are interesting in locating where the memory will be decrypted to (via mmap)
 * and where it jumps to the second decryption stub
 */
static kern_return_t
find_unpack_addresses(mach_vm_address_t start_addr, mach_vm_address_t end_addr, mach_vm_address_t *first_bp, mach_vm_address_t *second_bp)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    if (first_bp == NULL || second_bp == NULL)
    {
        NSLog(@"[ERROR] Bogus pointers.");
        return KERN_FAILURE;
    }
    if (start_addr > end_addr)
    {
        NSLog(@"[ERROR] Bogus addresses?");
        return KERN_FAILURE;
    }
    mach_vm_size_t len = end_addr - start_addr;
    kern_return_t kr = 0;
    vm_offset_t disasmBuf;
    mach_msg_type_number_t bytesRead = 0;
    NSLog(@"Reading first stage memory from address 0x%llx, 0x%llx bytes.", start_addr, len);
    if ( ( kr = mach_vm_read(g_targetTask, start_addr, len, &disasmBuf, &bytesRead)) )
    {
        NSLog(@"[ERROR] Failed to read memory: %d (%d, %s).", kr, __LINE__, __FUNCTION__);
        return KERN_FAILURE;
    }

    csh handle = 0;
    cs_insn *insn = NULL;
    size_t count = 0;
    cs_err cserr = 0;
    cs_mode mode = CS_MODE_32;
    if (targetMagic == MH_MAGIC_64)
    {
        mode = CS_MODE_64;
    }
    
    if ( (cserr = cs_open(CS_ARCH_X86, mode, &handle)) != CS_ERR_OK)
    {
        NSLog(@"[ERROR] Error opening capstone: %d.", cserr);
        return KERN_FAILURE;
    }
    /* enable detail - we need fields available in detail field */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    /* disassemble! */
    count = cs_disasm_ex(handle, (uint8_t*)disasmBuf, bytesRead, start_addr, 0, &insn);
    
    int found_bp1 = 0;
    int found_bp2 = 0;
    
    for (size_t i = 0; i < count; i++)
    {
        /* this looks up the push 1012h instruction which is the flags parameter to mmap inside the first stub */
        /* gives us where the first unpacking will occur */
        if (insn[i].id == X86_INS_PUSH &&
            insn[i].detail != NULL &&       // make sure there are details
            insn[i].detail->x86.op_count && // make sure there are operands
            insn[i].detail->x86.operands[0].imm == 0x1012 &&
            found_bp1 == 0)
        {
            NSLog(@"push 1012h address is: 0x%llx", insn[i].address);
            *first_bp = insn[i].address;
            found_bp1++;
        }
        /* this is the jmp after the unpacking code is called */
        /* starts executing the second stub */
        else if (insn[i].id == X86_INS_JMP &&
                 found_bp2 == 0)
        {
            /* the target address of the jump can be found in the imm */
            /* this is a bit different versus diStorm */
            *second_bp = insn[i].detail->x86.operands[0].imm;
            NSLog(@"Second stage JMP located at 0x%llx at address %llx %llx", *second_bp, insn[i].address, insn[i].detail->x86.operands[0].imm);
            found_bp2++;
            break;
        }
    }
    /* deallocate the memory we read and Capstone allocated memory */
    mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
    cs_free(insn, count);
    /* we got what we need, success */
    if (found_bp1 && found_bp2)
    {
        return KERN_SUCCESS;
    }
    else
    {
        return KERN_FAILURE;
    }
}

static kern_return_t
find_secondstage_entrypoint(mach_vm_address_t start, mach_vm_address_t *out_ep)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    if (out_ep == NULL)
    {
        NSLog(@"[ERROR] Bogus pointer.");
        return KERN_FAILURE;
    }
    mach_vm_size_t len = 20;
    kern_return_t kr = 0;
    vm_offset_t disasmBuf;
    mach_msg_type_number_t bytesRead = 0;
    if ( ( kr = mach_vm_read(g_targetTask, start, len, &disasmBuf, &bytesRead)) )
    {
        NSLog(@"[ERROR] Failed to read memory: %d.", kr);
    }
    
    csh handle = 0;
    cs_insn *insn = NULL;
    size_t count = 0;
    cs_err cserr = 0;
    cs_mode mode = CS_MODE_32;
    if (targetMagic == MH_MAGIC_64)
    {
        mode = CS_MODE_64;
    }
    
    if ( (cserr = cs_open(CS_ARCH_X86, mode, &handle)) != CS_ERR_OK)
    {
        NSLog(@"[ERROR] Error opening capstone: %d.", cserr);
        return KERN_FAILURE;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    count = cs_disasm_ex(handle, (uint8_t*)disasmBuf, bytesRead, start, 0, &insn);

    for (size_t i = 0; i < count; i++)
    {
        if (insn[i].id == X86_INS_JMP)
        {
            /* the target address of the jump can be found in the imm */
            /* this is a bit different versus diStorm */
            *out_ep = insn[i].detail->x86.operands[0].imm;
            NSLog(@"Second stage entrypoint JMP is: 0x%llx", *out_ep);
            mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
            cs_free(insn, count);
            return KERN_SUCCESS;
        }
    }
    
failure:
    mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
    cs_free(insn, count);
    return KERN_FAILURE;
}

/* find the OEP address
 * this should be the dyld_start inside dyld memory space
 */
static kern_return_t
find_oep(mach_vm_address_t start_addr, mach_vm_address_t *oep_bp)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    if (oep_bp == NULL)
    {
        NSLog(@"[ERROR] Bogus pointer.");
        return KERN_FAILURE;
    }
    mach_vm_size_t len = 0x200;
    kern_return_t kr = 0;
    vm_offset_t disasmBuf;
    mach_msg_type_number_t bytesRead = 0;
    if ( ( kr = mach_vm_read(g_targetTask, start_addr, len, &disasmBuf, &bytesRead)) )
    {
        NSLog(@"[ERROR] Failed to read memory: %d.", kr);
    }
    
    csh handle = 0;
    cs_insn *insn = NULL;
    size_t count = 0;
    cs_err cserr = 0;
    cs_mode mode = CS_MODE_32;
    if (targetMagic == MH_MAGIC_64)
    {
        mode = CS_MODE_64;
    }
    
    if ( (cserr = cs_open(CS_ARCH_X86, mode, &handle)) != CS_ERR_OK)
    {
        NSLog(@"[ERROR] Error opening capstone: %d.", cserr);
        return KERN_FAILURE;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    count = cs_disasm_ex(handle, (uint8_t*)disasmBuf, bytesRead, start_addr, 0, &insn);
    
    for (size_t i = 0; i < count; i++)
    {
        if (insn[i].id == X86_INS_JMP &&
            insn[i].detail->x86.operands[0].type == X86_OP_MEM)
        {
            NSLog(@"Found second stage entrypoint address!");
            /* the target address of the jump can be found in the imm */
            /* this is a bit different versus diStorm */
            NSLog(@"Found jump to OEP at address %llx", insn[i].address);
            *oep_bp = insn[i].address;
            cs_free(insn, count);
            mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
            return KERN_SUCCESS;
        }
    }

failure:
    mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
    cs_free(insn, count);
    return KERN_FAILURE;
}

#pragma mark -
#pragma mark All debugger related functions

/* this will install the debug port into the target task */
static void
install_debugger(int pid)
{
	kern_return_t kr = 0;
    /* exception mask related only to breakpoints */
	exception_mask_t mask = EXC_MASK_BREAKPOINT;
	/* get a send right */
	mach_port_t myself = mach_task_self();
	/* create a receive right in our task */
    if ( (kr = mach_port_allocate(myself, MACH_PORT_RIGHT_RECEIVE, &g_exceptionPort)) )
    {
        NSLog(@"[ERROR] mach_port_allocate failed: %d.", kr);
        return;
	}
    /* insert a send right: we will now have combined receive/send rights */
    if ( (kr = mach_port_insert_right(myself, g_exceptionPort, g_exceptionPort, MACH_MSG_TYPE_MAKE_SEND)) )
    {
        NSLog(@"[ERROR] mach_port_insert_right failed: %d.", kr);
        return;
    }
	/* retrieve the target task of our target process */
	if ( (kr = task_for_pid(myself, pid, &g_targetTask)) )
	{
		NSLog(@"[ERROR] retrieving task for pid! Do you have the correct permissions?\n");
		exit(1);
	}
	/* add an exception port in the target */
    if ( (kr = task_set_exception_ports(g_targetTask, mask, g_exceptionPort, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, MACHINE_THREAD_STATE)) )
    {
        NSLog(@"[ERROR] thread_set_exception_ports failed: %d.", kr);
        return;
    }
    /* create the debugger thread and start it */
    pthread_t exception_thread;
    if ((pthread_create(&exception_thread, (pthread_attr_t*)0, (void *(*)(void *))debug_loop, (void*)0)))
    {
        NSLog(@"[ERROR] Can't create debugger thread.");
        exit(1);
    }
    pthread_detach(exception_thread);
}

/*
 * the debug loop in a new thread that will be responsible for receiving and delivering the mach messages
 * mach_exc_server does the delivery magic
 */
static void
debug_loop(void)
{
    kern_return_t kr = 0;
    exc_msg_t   msg_recv = {0};
    reply_msg_t msg_resp = {0};
    /* loop forever, receiving and sending the exception mach messages */
    while (1)
    {
        msg_recv.Head.msgh_local_port = g_exceptionPort;
        msg_recv.Head.msgh_size = sizeof(msg_recv);
        
        kr = mach_msg(&(msg_recv.Head),				// message
                      MACH_RCV_MSG|MACH_RCV_LARGE,	// options -> timeout MACH_RCV_TIMEOUT
                      0,							// send size (irrelevant here)
                      sizeof(msg_recv),				// receive limit
                      g_exceptionPort,				// port for receiving
                      0,							// no timeout
                      MACH_PORT_NULL);				// notify port (irrelevant here)
        
        if (kr == MACH_RCV_TIMED_OUT)
        {
            NSLog(@"[ERROR] Receive message timeout!");
            continue;
        }
        else if (kr != MACH_MSG_SUCCESS)
        {
            NSLog(@"[ERROR] Got bad Mach message on receive!");
            continue;
        }

        /* dispatch the message */
        mach_exc_server(&msg_recv.Head, &msg_resp.Head);
        /* now msg_resp.RetCode contains return value of catch_exception_raise_state_identify() */
        kr = mach_msg(&(msg_resp.Head),			// message
                      MACH_SEND_MSG,			// options -> timeout MACH_SEND_TIMEOUT
                      msg_resp.Head.msgh_size,	// send size
                      0,						// receive limit (irrelevant here)
                      MACH_PORT_NULL,			// port for receiving (none)
                      0,						// no timeout
                      MACH_PORT_NULL);			// notify port (we don't want one)
        
        if (kr == MACH_SEND_TIMED_OUT)
        {
            NSLog(@"[ERROR] Send message timeout!");
            continue;
        }
        else if (kr != MACH_MSG_SUCCESS)
        {
            NSLog(@"[ERROR] Got bad Mach message on response!");
            continue;
        }
    }
}

/* this is just here because compiler complaints... */
extern kern_return_t
catch_mach_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t codeCnt)
{
    return KERN_FAILURE;
}

/* this is just here because compiler complaints... */
extern kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port, exception_type_t exception, const exception_data_t code, mach_msg_type_number_t codeCnt, int *flavor, const thread_state_t old_state, mach_msg_type_number_t old_stateCnt, thread_state_t new_state, mach_msg_type_number_t *new_stateCnt)
{
	return KERN_FAILURE;
}

/*
 * the function that receives the exceptions
 * this version receives the thread state and sets the new one
 * we avoid calls to thread_get_state and thread_set_state, improving performance
 */
extern kern_return_t
catch_mach_exception_raise_state_identity (mach_port_t exception_port,
                                           mach_port_t thread,
                                           mach_port_t task,
										   exception_type_t exception,
                                           exception_data_t code,
                                           mach_msg_type_number_t codeCnt,
										   int *flavor,
                                           thread_state_t old_state,
                                           mach_msg_type_number_t old_stateCnt,
										   thread_state_t new_state,
                                           mach_msg_type_number_t *new_stateCnt)
{
#pragma unused(exception_port)
#pragma unused(task)

    /* to make things easier we just have a single eip which will hold 32 or 64bits addresses */
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE)
    {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE32)
        {
            eip = ts->uts.ts32.__eip;
        }
        else if (ts->tsh.flavor == x86_THREAD_STATE64)
        {
            eip = ts->uts.ts64.__rip;
        }
    }
    /* int3 EIP/RIP is one byte ahead */
    eip--;
    NSLog(@"Breakpoint hit at address 0x%llx, flavor %d exception %d.", eip, *flavor, exception);
    /* process the breakpoint - locate and execute the callback for each breakpoint */
    if (exception == EXC_BREAKPOINT)
    {
        struct soft_bp *el = NULL;
        LL_FOREACH(g_breakpoints, el)
        {
            if (el->address == eip)
            {
                /* update the state count here */
                *new_stateCnt = MACHINE_THREAD_STATE_COUNT;
                /* the exception processor needs to set the new_state and new_stateCnt to updated values else CABOOOM */
                return el->exception_processor(task, flavor, old_state, new_state);
            }
        }
    }
    return KERN_SUCCESS;
}

#pragma mark -
#pragma mark The functions that deal with the breakpoints

/* the first breakpoint we retrieve the address and size where the original binary will be unpacked to.
 * the breakpoint relies on instruction "push 1012h"
 * which contains the flags passed to mmap the unpacking area.
 * XXX: better then this would be to breakpoint on the call and just dump the parameters from the stack!
 */
static kern_return_t
process_firstbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE)
    {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE32)
        {
            eip = ts->uts.ts32.__eip;
            eip--;
            delete_breakpoint(thread, eip);
            /* ebx contains the length, ecx the address */
            g_unpacking_addr = ts->uts.ts32.__ecx;
            g_unpacking_size = ts->uts.ts32.__ebx;
            NSLog(@"Unpacking address: 0x%x Length: 0x%x ", ts->uts.ts32.__ecx, ts->uts.ts32.__ebx);
            ts->uts.ts32.__eip = (unsigned int)eip;
            memcpy(new_state, old_state, x86_THREAD_STATE32_COUNT * sizeof(natural_t));
        }
        /* XXX: not finished */
        else if (ts->tsh.flavor == x86_THREAD_STATE64)
        {
            eip = ts->uts.ts64.__rip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts64.__rip = eip;
            memcpy(new_state, old_state, x86_THREAD_STATE64_COUNT * sizeof(natural_t));
        }
    }
    return KERN_SUCCESS;
}

/* here we just breakpointed on the first jump that will jump to the final stage 1 jump responsible
 * for starting the second stage that was also unpacked
 * we disassemble the instruction and retrieve the target address
 * it's done this way because there is data in the middle of the disassembly that can create problems
 *
 * NOTE: what we processed in process_firstbreakpoint() is the whote unpacked area but we don't know
 *       from that info where the second stub is located at. it's here where we find it.
 *       The second stage is fully unpacked when we hit this breakpoint.
 */
static kern_return_t
process_secondbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE)
    {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE32)
        {
            eip = ts->uts.ts32.__eip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts32.__eip = (unsigned int)eip;
            memcpy(new_state, old_state, x86_THREAD_STATE32_COUNT * sizeof(natural_t));
            /* locate the next breakpoint and set it */
            mach_vm_address_t bp = 0;
#if DUMP_STAGES == 1
            mach_vm_size_t len = g_unpacking_size;
            vm_offset_t unpacked_data;
            mach_msg_type_number_t bytesread = 0;
            kern_return_t kr = 0;
            kr = mach_vm_read(g_targetTask, g_unpacking_addr, len, &unpacked_data, &bytesread);
            if (kr == KERN_SUCCESS)
            {
                char *target = NULL;
                size_t target_size = strlen(targetFile) + 20 + 1;
                target = malloc(target_size);
                snprintf(target, target_size , "%s_2ndstub", targetFile);
                target[target_size-1] = '\0';
                FILE *fileToWrite = fopen(target, "wb");
                fwrite((void*)unpacked_data, len, 1, fileToWrite);
                fclose(fileToWrite);
                mach_vm_deallocate(mach_task_self(), unpacked_data, bytesread);
            }
#endif
            if (find_secondstage_entrypoint(eip, &bp) == KERN_SUCCESS)
            {
                insert_breakpoint(thread, bp, process_thirdbreakpoint, "ccc");
            }
        }
        /* XXX: not finished */
        else if (ts->tsh.flavor == x86_THREAD_STATE64)
        {
            eip = ts->uts.ts64.__rip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts64.__rip = eip;
            memcpy(new_state, old_state, x86_THREAD_STATE64_COUNT * sizeof(natural_t));
        }
    }
    return KERN_SUCCESS;
}

/* this breakpoint is set on the first instruction of the second stage
 * now we can disassemble the second stub and find out the jump to the original entry point
 */
static kern_return_t
process_thirdbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE)
    {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE32)
        {
            eip = ts->uts.ts32.__eip;
            eip--;
            delete_breakpoint(thread, eip);
            mach_vm_address_t oep_bp = 0;
            find_oep(eip, &oep_bp);
            ts->uts.ts32.__eip = (unsigned int)eip;
            memcpy(new_state, old_state, x86_THREAD_STATE32_COUNT * sizeof(natural_t));
            if (oep_bp == 0)
            {
                NSLog(@"OEP breakpoint not found, impossible to proceed.");
                exit(-1);
            }

            NSLog(@"Inserting breakpoint to find OEP at 0x%llx ...", oep_bp);
            insert_breakpoint(thread, oep_bp, process_oepbreakpoint, "ddd");
        }
        /* XXX: not finished */
        else if (ts->tsh.flavor == x86_THREAD_STATE64)
        {
            eip = ts->uts.ts64.__rip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts64.__rip = eip;
            memcpy(new_state, old_state, x86_THREAD_STATE64_COUNT * sizeof(natural_t));
        }
    }
    return KERN_SUCCESS;
}

/* on this breakpoint we are on the jump to OEP instruction
 * we dump the original binary and kill the original process
 */
static kern_return_t
process_oepbreakpoint(mach_port_t thread, int *flavor, thread_state_t old_state, thread_state_t new_state)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    mach_vm_address_t eip = 0;
    if (*flavor == x86_THREAD_STATE)
    {
        x86_thread_state_t *ts = (x86_thread_state_t*)old_state;
        if (ts->tsh.flavor == x86_THREAD_STATE32)
        {
            eip = ts->uts.ts32.__eip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts32.__eip = (unsigned int)eip;
            mach_vm_size_t len = 4;
            kern_return_t kr = 0;
            vm_offset_t disasmBuf;
            mach_msg_type_number_t bytesRead = 0;
            if ( ( kr = mach_vm_read(g_targetTask, ts->uts.ts32.__eax, len, &disasmBuf, &bytesRead)) )
            {
                NSLog(@"[ERROR] Failed to read OEP: %d.", kr);
            }
            NSLog(@"OEP is %x", *(uint32_t*)disasmBuf);
            mach_vm_deallocate(mach_task_self(), disasmBuf, bytesRead);
            memcpy(new_state, old_state, x86_THREAD_STATE32_COUNT * sizeof(natural_t));
            delete_all_breakpoints(thread);
            /* XXX: we ignore return value here... needs to be fixed */
            process_and_dump_to_disk();
            pid_t target_pid = 0;
            pid_for_task(g_targetTask, &target_pid);
            kill(target_pid, SIGKILL);
            l_dumping_finished = 1;
        }
        /* XXX: not finished */
        else if (ts->tsh.flavor == x86_THREAD_STATE64)
        {
            eip = ts->uts.ts64.__rip;
            eip--;
            delete_breakpoint(thread, eip);
            ts->uts.ts64.__rip = eip;
            memcpy(new_state, old_state, x86_THREAD_STATE64_COUNT * sizeof(natural_t));
        }
    }
    return KERN_SUCCESS;
}

static kern_return_t
process_and_dump_to_disk(void)
{
    NSLog(@"Executing %s...", __FUNCTION__);
    FILE *fileToWrite = fopen(targetFile, "wb");
    vm_offset_t writeBuf;
    mach_msg_type_number_t bytesRead = 0;
    mach_vm_size_t len = g_unpacking_size;
    if ( mach_vm_read(g_targetTask, g_unpacking_addr, len, &writeBuf, &bytesRead) != KERN_SUCCESS )
    {
        NSLog(@"[ERROR] Failed to read memory.");
        return KERN_FAILURE;
    }
    /* now we need to process the header and start writing */
    struct mach_header *mh = (struct mach_header*)writeBuf;
    int headerSize = sizeof(struct mach_header);
    switch (mh->magic)
    {
        case MH_MAGIC_64:
            headerSize = sizeof(struct mach_header_64);
            break;
        case MH_MAGIC:
            break;
        default:
            NSLog(@"[ERROR] Buffer doesn't contain a mach-o file!");
            mach_vm_deallocate(mach_task_self(), writeBuf, bytesRead);
            return KERN_FAILURE;
    }
    char *lc_addr = (char*)writeBuf + headerSize;
    char *buf_addr = (char*)writeBuf;
    /* iterate over commands and dump
     * we just care about LC_SEGMENT commands that contain data 
     * XXX: should be true :X
     */
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        struct load_command *lc = (struct load_command*)lc_addr;
        /* 32 bits targets */
        if (lc->cmd == LC_SEGMENT)
        {
            struct segment_command *sc = (struct segment_command*)lc_addr;
            /* skip PAGEZERO */
            if (sc->vmaddr == 0)
            {
                lc_addr += lc->cmdsize;
                continue;
            }
            /* __TEXT should be the first command, which includes the Mach-O header */
            /* XXX: this should be more robust and without less assumptions */
            if (strncmp(sc->segname, "__TEXT", 16) == 0)
            {
                NSLog(@"Dumping %x from %s", *(int*)buf_addr, sc->segname);
                /* dump to disk using the file size instead of vm size */
                fwrite((void*)buf_addr, sc->filesize, 1, fileToWrite);
                /* advance buffer by the vm size */
                buf_addr += sc->vmsize;
            }
            /* remaining commands */
            else
            {
                NSLog(@"Dumping %x from %s", *(int*)buf_addr, sc->segname);
                fwrite((void*)buf_addr, sc->filesize, 1, fileToWrite);
                buf_addr += sc->vmsize;
            }
        }
        /* XXX: not finished */
        if (lc->cmd == LC_SEGMENT_64)
        {
            
        }
        lc_addr += lc->cmdsize;
    }
    fclose(fileToWrite);
    mach_vm_deallocate(mach_task_self(), writeBuf, bytesRead);
    return KERN_SUCCESS;
}
