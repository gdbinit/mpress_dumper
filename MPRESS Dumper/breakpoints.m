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
 * breakpoints.c
 *
 */

#include "breakpoints.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/mach_vm.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

struct soft_bp *g_breakpoints = NULL;

/* local functions */
static kern_return_t set_protection (mach_port_t task, mach_vm_address_t address, const char *protection, const uint32_t size);
static vm_prot_t get_protection(mach_port_t task, mach_vm_address_t address);
static vm_prot_t parse_protection (const char * protection);
static const char * unparse_protection (vm_prot_t p);

static kern_return_t verify_int3(mach_port_t task, mach_vm_address_t address);
static kern_return_t write_int3(mach_port_t task, mach_vm_address_t address);
static kern_return_t restore_byte(mach_port_t task, mach_vm_address_t addr);

#pragma mark Exported functions 

/*
 Software breakpoint flow:
 1) Insert breakpoint
 2) Debug loop
 3) Breakpoint hit
 3.1) Fix EIP
 3.2) Remove int3 and restore original byte
 3.3) If restore (single step), then breakpoint on the next byte
 3.4) Continue
 3.5) Breakpoint hit
 3.6) FIX EIP, remove int3, continue
 3.7) If not restore, then continue
 */
kern_return_t
insert_breakpoint(mach_port_t task, mach_vm_address_t address, void* exception_processor, char *processor_name)
{
	kern_return_t kr = 0;
    mach_vm_size_t len = 1;
    vm_offset_t originalopcode = 0;
	mach_msg_type_number_t bytesread = 0;
    
    // verify if current address is already on the list
    struct soft_bp *el = NULL;
    LL_FOREACH(g_breakpoints, el)
    {
        if (el->address == address)
        {
            break;
        }
    }
    if (el != NULL)
    {
        NSLog(@"[ERROR] Address %p is already into the linked list!", (void*)address);
        // XXX: shouldn't this be KERN_FAILURE ?
        return 0;
    }
    
    struct soft_bp *new = malloc(sizeof(struct soft_bp));
    if (new != NULL)
    {
        new->address = address;
        LL_PREPEND(g_breakpoints, new);
    }
    else
    {
        NSLog(@"[ERROR] Allocation for new element failed!");
        return KERN_FAILURE;
    }
	NSLog(@"Inserting software breakpoint at 0x%llx", address);
	// read & store original byte
	// originalopcode is a "Out-pointer to dynamic array of bytes returned by the read."
	kr = mach_vm_read(task, address, len, &originalopcode, &bytesread);
    if (kr)
    {
        NSLog(@"failed to read memory!");
    }
	// copy the original byte into our breakpoints information structure
	new->originalopcode = *(unsigned char *)originalopcode;
	// copy the original permissions into our information structure
	new->originalprotection = get_protection(task, address);
	// modify memory permissions
	set_protection(task, address, "rwx", 1);
	// replace it with int3
	write_int3(task, address);
	// restore original memory permissions
	set_protection(task, address, unparse_protection(new->originalprotection), 1);
	
	// everything went well so we can add it to the breakpoint list
	new->address = address;
	new->exception_processor = exception_processor;
    size_t name_len = strlen(processor_name) + 1;
	new->name = malloc(name_len);
    strlcpy(new->name, processor_name, name_len);
	kr = mach_vm_deallocate(mach_task_self(), originalopcode, len);
	return KERN_SUCCESS;
}

/*
 * this will restore the original byte and remove the breakpoint from the list
 */
kern_return_t
delete_breakpoint(mach_port_t task, mach_vm_address_t address)
{
    struct soft_bp *el = NULL;
    struct soft_bp *tmp = NULL;
	// remove from breakpoints list
    LL_FOREACH_SAFE(g_breakpoints, el, tmp)
    {
        if (el->address == address)
        {
            restore_byte(task, address);
            LL_DELETE(g_breakpoints, el);
            free(el->name);
            free(el);
            break;
        }
    }
	return KERN_SUCCESS;
}

#pragma mark Internal

/*
 * restore the original byte at the breakpoint address
 */
static kern_return_t
restore_byte(mach_port_t task, mach_vm_address_t addr)
{
	kern_return_t kr = 0;
	vm_offset_t bytetorestore = 0;
	mach_msg_type_number_t len = 1;
    
	// verify it's an int3 byte that we are trying to restore
	if (verify_int3(task, addr))
    {
        NSLog(@"Target address doesn't contain a INT3 instruction!");
        return KERN_FAILURE;
    }
	// modify memory permissions
	set_protection(task, addr, "rwx", 1);
    struct soft_bp *el = NULL;
    int found = 0;
    LL_FOREACH(g_breakpoints, el)
    {
        if (el->address == addr)
        {
            bytetorestore = el->originalopcode;
            // replace it with original byte
            kr = mach_vm_write(task, addr, (pointer_t)&bytetorestore, len);
            // we should restore the original memory permissions :-)
            set_protection(task, addr, unparse_protection(el->originalprotection), 1);
            found++;
            break;
        }
    }
    if (found == 0)
    {
        NSLog(@"No original opcode to be restored found for %p!", (void*)addr);
        return KERN_FAILURE;
    }
	return KERN_SUCCESS;
}

/*
 * delete breakpoints from all addresses and the list
 */
kern_return_t
delete_all_breakpoints(mach_port_t task)
{
    struct soft_bp *el = NULL;
    struct soft_bp *tmp = NULL;
	// remove from breakpoints list
    LL_FOREACH_SAFE(g_breakpoints, el, tmp)
    {
        NSLog(@"Found a breakpoint to remove at %p.", (void*)el->address);
        // replace int3 with original byte
        restore_byte(task, el->address);
        LL_DELETE(g_breakpoints, el);
        free(el->name);
        free(el);
    }
	return KERN_SUCCESS;
}

/*
 * verify if address contains an int3
 */
static kern_return_t
verify_int3(mach_port_t task, mach_vm_address_t address)
{
	kern_return_t kr = 0;
	mach_vm_size_t len = 1;
	vm_offset_t opcode = 0;
	mach_msg_type_number_t bytesread = 0;
	// verify it's an int3 byte that we are trying to restore
	kr = mach_vm_read(task, address, len, &opcode, &bytesread);
    
	if (*(unsigned char *)opcode != 0xCC)
	{
		NSLog(@"Destination address %p does not contain an int3 byte!", (void*)address);
		return KERN_FAILURE;
	}
	// deallocate mach_vm_read memory
	kr = mach_vm_deallocate(mach_task_self(), opcode, len);
    return KERN_SUCCESS;
}

/*
 * write an int3 byte to the address
 */
static kern_return_t
write_int3(mach_port_t task, mach_vm_address_t address)
{
	kern_return_t kr = 0;
	uint8_t opcode = 0xCC;
	mach_msg_type_number_t len = 1;
	// write the int3
	kr = mach_vm_write(task, address, (vm_offset_t)&opcode, len);
    return KERN_SUCCESS;
}

#pragma mark Memory related functions

/*
 * this will parse protection in the format --- (r,w,x)
 * and convert to vm_prot_t so we can pass it to set_protection or something else
 */
static vm_prot_t
parse_protection (const char * protection)
{
	// default values
	vm_prot_t read = 0;
	vm_prot_t write = 0;
	vm_prot_t execute = 0;
	// parse the protection input
	if (protection[0] == 'r')
		read = VM_PROT_READ;
	if (protection[1] == 'w')
		write = VM_PROT_WRITE | VM_PROT_COPY; // iOS requires this!
	if (protection[2] == 'x')
		execute = VM_PROT_EXECUTE;
	// and convert it to vm_prot_t type
	return (read | write | execute);
}

static const char *
unparse_protection (vm_prot_t p)
{
    switch (p)
    {
        case VM_PROT_NONE:
            return "---";
        case VM_PROT_READ:
            return "r--";
        case VM_PROT_WRITE:
            return "-w-";
        case VM_PROT_READ | VM_PROT_WRITE:
        case VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY:
            return "rw-";
        case VM_PROT_EXECUTE:
            return "--x";
        case VM_PROT_EXECUTE | VM_PROT_READ:
            return "r-x";
        case VM_PROT_EXECUTE | VM_PROT_WRITE:
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_COPY:
            return "-wx";
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ:
        case VM_PROT_EXECUTE | VM_PROT_WRITE | VM_PROT_READ | VM_PROT_COPY:
            return "rwx";
        default:
            return "???";
    }
}

/*
 * set the permissions on a given memory address
 */
static kern_return_t
set_protection (mach_port_t task, mach_vm_address_t address, const char *protection, const uint32_t size)
{
	kern_return_t kr = 0;
	mach_vm_size_t len = size;
    vm_prot_t new_protection = parse_protection(protection);
	// modify memory permissions
    kr = mach_vm_protect(task, address, len, FALSE, new_protection);
    return KERN_SUCCESS;
}

/*
 * retrieve the protection flags of any given address
 * don't forget that OS X works on pages
 * XXX: needs improvement with submaps
 */
static vm_prot_t
get_protection(mach_port_t task, mach_vm_address_t address)
{
	kern_return_t kr = 0;
	vm_region_basic_info_data_64_t info = {0};
    
	mach_vm_size_t size = 0;
	mach_port_t object_name = 0;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    kr = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
	// we just return the protection field
	return info.protection;
}
