#include <CoreAudio/CoreAudio.h>
#include <stdio.h>
int main(void) {
    AudioObjectPropertyAddress address = { kAudioHardwarePropertyDefaultOutputDevice, kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain };
    AudioDeviceID device = kAudioObjectUnknown;
    UInt32 size = sizeof(device);
    puts("Querying CoreAudio default output device"); fflush(stdout);
    OSStatus status = AudioObjectGetPropertyData(kAudioObjectSystemObject, &address, 0, NULL, &size, &device);
    printf("CoreAudio query completed; status=%d\n", (int)status);
    return status == noErr ? 0 : 1;
}
