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
 * mdumperAppDelegate.m
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

#import "mdumperAppDelegate.h"
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <mach/thread_status.h>

#include "dumper.h"

#define MPRESS_SEGNAME "__MPRESS__v"

extern uint32 targetMagic;

@implementation mdumperAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    source = @"";
    target = @"";
}

/* exit the application if we close the window */
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
    return YES;
}

- (IBAction)startDump:(id)sender
{
    /* verify if we have source and target */
    NSAlert* msgBox = [[NSAlert alloc] init];
    [msgBox setAlertStyle:NSCriticalAlertStyle];
    [msgBox setMessageText:@"Missing files!"];
    int showAlert = 0;
    if ([source isEqualToString:@""])
    {
        [msgBox setInformativeText:@"Source file is missing."];
        showAlert++;
    }
    else if ([target isEqualToString:@""])
    {
        [msgBox setInformativeText:@"Target file is missing."];
        showAlert++;
    }
    if (showAlert)
    {
        [msgBox beginSheetModalForWindow:self.window
                           modalDelegate:self
                          didEndSelector:nil
                             contextInfo:nil];
        NSLog(@"Missing source or target file!");
        return;
    }
    
    NSLog(@"Asked to dump from %@ to %@", source, target);
    
    /* verify if target is a valid mach-o and MPRESS file */
    NSError *error;
    sourceBinary = [NSMutableData dataWithContentsOfURL:sourceURL
                                                options:NSDataReadingMappedAlways
                                                  error:&error];
    if (error)
    {
        NSLog(@"Failed to read source file!");
        return;
    }
    struct mach_header *mh = (struct mach_header*)[sourceBinary bytes];
    int headerSize = sizeof(struct mach_header);
    
    switch (mh->magic)
    {
        case MH_MAGIC:
        {
            targetMagic = MH_MAGIC;
            break;
        }
        case MH_MAGIC_64:
        {
            targetMagic = MH_MAGIC_64;
            headerSize = sizeof(struct mach_header_64);
            break;
        }
        case FAT_CIGAM:
        case FAT_MAGIC:
        {
            NSLog(@"Fat targets not supported yet!");
            return;
        }
        default:
        {
            NSLog(@"Invalid Mach-O file or not supported!");
            return;
        }
    }
    
    /* test if there any commands and they make some sense */
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        /* XXX: add error msg to the gui */
        NSLog(@"Mach-O header contains invalid data.");
        return;
    }
    
    /* verify if there's a MPRESS segment */
    char *loadCmd_addr = (char*)mh + headerSize;
    int foundMPRESS = 0;
    mach_vm_address_t entrypoint = 0;
    mach_vm_address_t mpress_seg_vmaddr = 0;
    uint64_t mpress_seg_vmsize = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        struct load_command *loadCmd = (struct load_command*)loadCmd_addr;
        /* XXX: needs to be reworked in case there's another matching segment with bogus data */
        if (loadCmd->cmd == LC_SEGMENT)
        {
            struct segment_command *segCmd = (struct segment_command*)loadCmd_addr;
            if (strncmp(segCmd->segname, MPRESS_SEGNAME, strlen(MPRESS_SEGNAME)) == 0)
            {
                mpress_seg_vmaddr = segCmd->vmaddr;
                mpress_seg_vmsize = segCmd->vmsize;
                foundMPRESS++;
            }
        }
        /* XXX: needs to be reworked in case there's another matching segment with bogus data */
        else if (loadCmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segCmd = (struct segment_command_64*)loadCmd_addr;
            if (strncmp(segCmd->segname, MPRESS_SEGNAME, strlen(MPRESS_SEGNAME)) == 0)
            {
                mpress_seg_vmaddr = segCmd->vmaddr;
                mpress_seg_vmsize = segCmd->vmsize;
                foundMPRESS++;
            }
        }
        /* retrieve MPRESS entrypoint */
        else if (loadCmd->cmd == LC_UNIXTHREAD)
        {
            uint32_t flavor = *(uint32_t*)(loadCmd_addr + sizeof(struct thread_command));
            if (flavor == x86_THREAD_STATE32)
            {
                x86_thread_state32_t *ts = (x86_thread_state32_t*)(loadCmd_addr + sizeof(struct thread_command) + 2 * sizeof(uint32_t));
                entrypoint = ts->__eip;
                NSLog(@"Entrypoint is %x", ts->__eip);
            }
            else if (flavor == x86_THREAD_STATE64)
            {
                x86_thread_state64_t *ts = (x86_thread_state64_t*)(loadCmd_addr + sizeof(struct thread_command) + 2 * sizeof(uint32_t));
                entrypoint = ts->__rip;
                NSLog(@"Entrypoint is %llx", ts->__rip);
            }
        }
        loadCmd_addr += loadCmd->cmdsize;
    }
    
    if (foundMPRESS)
    {
        NSLog(@"MPRESS binary found!");
        /* we need the end address info for disassembling */
        mach_vm_address_t endAddress = mpress_seg_vmaddr + mpress_seg_vmsize;
        NSAlert *alert = [[NSAlert alloc] init];
        if ( unpack_mpress([source UTF8String], [target UTF8String], entrypoint, endAddress) == 0)
        {
            [alert addButtonWithTitle:@"OK"];
            [alert setMessageText:@"Dumping finished!"];
            [alert setAlertStyle:NSWarningAlertStyle];
            [alert beginSheetModalForWindow:self.window
                              modalDelegate:self
                             didEndSelector:nil
                                contextInfo:nil];
        }
        else
        {
            [alert addButtonWithTitle:@"OK"];
            [alert setMessageText:@"Dumping error!"];
            [alert setAlertStyle:NSCriticalAlertStyle];
            [alert beginSheetModalForWindow:self.window
                              modalDelegate:self
                             didEndSelector:nil
                                contextInfo:nil];
        }
    }
}

- (IBAction)selectSourceFile:(id)sender
{
    NSOpenPanel* openDialog = [NSOpenPanel openPanel];
    /* only allow a single target to be selected */
    [openDialog setAllowsMultipleSelection:NO];
    /* go deep into application bundles */
    [openDialog setTreatsFilePackagesAsDirectories:YES];
    /* Enable the selection of files in the dialog. */
    [openDialog setCanChooseFiles:YES];
    /* Disable the selection of directories in the dialog. */
    [openDialog setCanChooseDirectories:NO];
    /* Display the dialog.  If the OK button was pressed, process the file. */
    if ( [openDialog runModal] == NSFileHandlingPanelOKButton )
    {
        // Get an array containing the full filenames of all
        // files and directories selected.
        NSArray* files = [openDialog URLs];
        /* we only have a single file */
        sourceURL = [files objectAtIndex:0];
        source = [sourceURL path];
        NSLog(@"%@", source);
        /* update the text field */
        [self.sourceFile setStringValue:source];
    }
}

- (IBAction)selectOutputFile:(id)sender
{
    NSSavePanel* saveDialog = [NSSavePanel savePanel];
    /* Display the dialog.  If the OK button was pressed, process the files. */
    if ( [saveDialog runModal] == NSFileHandlingPanelOKButton )
    {
        targetURL = [saveDialog URL];
        target = [targetURL path];
        NSLog(@"%@", target);
        /* update the text field */
        [self.targetFile setStringValue:target];
    }
}

- (IBAction)updateSourceFile:(id)sender
{
    source = [self.sourceFile stringValue];
    sourceURL = [NSURL fileURLWithPath:source];
    NSLog(@"New source value %@", source);
}

- (IBAction)updateTargetFile:(id)sender
{
    target = [self.targetFile stringValue];
    targetURL = [NSURL fileURLWithPath:target];
    NSLog(@"New target value %@", target);
}

@end
