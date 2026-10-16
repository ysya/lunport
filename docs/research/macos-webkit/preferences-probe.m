#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <objc/message.h>

static void printFeatures(WKPreferences *preferences, NSArray *features, const char *label) {
    printf("\n%s\n", label);
    for (id feature in features) {
        SEL keySelector = NSSelectorFromString(@"key");
        if (![feature respondsToSelector:keySelector]) continue;
        NSString *key = ((id (*)(id, SEL))objc_msgSend)(feature, keySelector);
        if (![key isEqualToString:@"UseGPUProcessForDOMRenderingEnabled"] &&
            ![key isEqualToString:@"UseGPUProcessForCanvasRenderingEnabled"] &&
            ![key isEqualToString:@"UseGPUProcessForWebGLEnabled"] &&
            ![key isEqualToString:@"UseGPUProcessForMediaEnabled"] &&
            ![key isEqualToString:@"MediaPlaybackEnabled"]) continue;
        BOOL enabled = ((BOOL (*)(id, SEL, id))objc_msgSend)(preferences, NSSelectorFromString(@"_isEnabledForFeature:"), feature);
        printf("%s=%s\n", key.UTF8String, enabled ? "true" : "false");
    }
}

int main(void) {
    @autoreleasepool {
        SEL featuresSelector = NSSelectorFromString(@"_features");
        if (![[WKPreferences class] respondsToSelector:featuresSelector]) return 2;
        NSArray *features = ((id (*)(id, SEL))objc_msgSend)([WKPreferences class], featuresSelector);
        WKWebViewConfiguration *configuration = [WKWebViewConfiguration new];
        printFeatures(configuration.preferences, features, "Default in-memory configuration");
        configuration.mediaTypesRequiringUserActionForPlayback = WKAudiovisualMediaTypeAll;
        printFeatures(configuration.preferences, features, "Public API requiring user action for all media playback");
        SEL disableSelector = NSSelectorFromString(@"_disableMediaPlaybackRelatedFeatures");
        if (![configuration.preferences respondsToSelector:disableSelector]) return 3;
        ((void (*)(id, SEL))objc_msgSend)(configuration.preferences, disableSelector);
        printFeatures(configuration.preferences, features, "Private API disabling media playback related features in memory only");
    }
    return 0;
}
