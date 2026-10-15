#import <AppKit/AppKit.h>

// Called only on Tauri's main thread. No WKWebView, CFUserNotification, private
// API, or system-service manipulation. An app-modal NSAlert owns its own window.
long sshelter_native_alert(const char *title, const char *message,
                          const char *const *buttons, unsigned long count) {
    @autoreleasepool {
        NSAlert *alert = [NSAlert new];
        alert.alertStyle = NSAlertStyleWarning;
        alert.messageText = [NSString stringWithUTF8String:title];
        alert.informativeText = [NSString stringWithUTF8String:message];
        for (unsigned long i = 0; i < count; ++i) {
            [alert addButtonWithTitle:[NSString stringWithUTF8String:buttons[i]]];
        }
        [NSApp activateIgnoringOtherApps:YES];
        [alert.window center];
        return [alert runModal] - NSAlertFirstButtonReturn;
    }
}
