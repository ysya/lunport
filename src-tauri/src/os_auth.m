#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

// Touch ID, or the Mac's password, for os_auth.rs. The system shows its own question; nothing here runs on the main thread, and
// os_auth_confirm blocks until the person answers, so it is called on a background thread.

// How long os_auth_confirm waits for the person.
static const int64_t CONFIRM_WITHIN_SECONDS = 120;

// 1 when this Mac can ask the person to confirm with Touch ID or its password, 0 when it cannot.
int os_auth_available(void) {
    @autoreleasepool {
        LAContext *context = [LAContext new];
        return [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil] ? 1 : 0;
    }
}

// Asks the person to confirm `reason` (the system shows "<app> is trying to <reason>.") and waits for the answer: 1 allowed; 0 refused,
// cancelled or not answered within CONFIRM_WITHIN_SECONDS; -1 when the Mac cannot ask.
int os_auth_confirm(const char *reason) {
    @autoreleasepool {
        NSString *text = reason == NULL ? nil : [NSString stringWithUTF8String:reason];
        LAContext *context = [LAContext new];
        if (text.length == 0 || ![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil]) {
            return -1;
        }
        dispatch_semaphore_t answered = dispatch_semaphore_create(0);
        __block int answer = 0;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:text
                          reply:^(BOOL success, NSError *error) {
                              if (success) {
                                  answer = 1;
                              } else if ([error.domain isEqualToString:LAErrorDomain] &&
                                         (error.code == LAErrorPasscodeNotSet || error.code == LAErrorNotInteractive)) {
                                  answer = -1;
                              }
                              dispatch_semaphore_signal(answered);
                          }];
        // The context is held until the answer comes: a context that goes away cancels its question.
        if (dispatch_semaphore_wait(answered, dispatch_time(DISPATCH_TIME_NOW, CONFIRM_WITHIN_SECONDS * (int64_t)NSEC_PER_SEC)) != 0) {
            [context invalidate];
            return 0;
        }
        return answer;
    }
}
