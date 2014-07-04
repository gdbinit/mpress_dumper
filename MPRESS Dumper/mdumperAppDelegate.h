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
 * mdumperAppDelegate.h
 *
 */

#import <Cocoa/Cocoa.h>

@interface mdumperAppDelegate : NSObject <NSApplicationDelegate>
{
    NSString *source;
    NSURL *sourceURL;
    NSURL *targetURL;
    NSString *target;
    NSMutableData *sourceBinary;
}
@property (assign) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSTextField *sourceFile;
@property (weak) IBOutlet NSTextField *targetFile;

- (IBAction)startDump:(id)sender;
- (IBAction)selectSourceFile:(id)sender;
- (IBAction)selectOutputFile:(id)sender;
- (IBAction)updateSourceFile:(id)sender;
- (IBAction)updateTargetFile:(id)sender;

@end
