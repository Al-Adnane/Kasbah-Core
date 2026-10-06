/*
 * kextd.c — Kasbah user-space daemon (Tier 2 bridge)
 *
 * Connects to the KasbahGuard kext via IOKit, drains the kernel event ring
 * (camera/mic open events, tamper alerts), and bridges them to stdout as
 * JSON lines — one per event. The desktop app (or any SIEM tail process)
 * consumes the stream for real-time kernel-tier visibility.
 *
 * Build:  cd kernel && make kextd
 * Run:    sudo build/kextd          (root is required for IOServiceOpen on
 *                                    a non-entitled user client)
 * Output: {"type":"camera-open","pid":4242,"identity":"...","ts":...}
 *
 * Honest scope: this daemon is useful once the kext is signed and loaded
 * (see README.md). Without the kext it exits cleanly with a message — the
 * user-space sentinels (Tier 1) remain fully active regardless.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach_time.h>
#include <unistd.h>

#define KASBAH_MAX_EVENTS 256

struct kasbah_event {
    uint64_t timestamp_ns;
    uint32_t type;
    uint32_t pid;
    char     identity[128];
};

#define KASBAH_EV_CAMERA_OPEN  1
#define KASBAH_EV_MIC_OPEN     2
#define KASBAH_EV_DEVICE_CLOSE 3
#define KASBAH_EV_TAMPER       4

static const char *event_name(uint32_t type) {
    switch (type) {
        case KASBAH_EV_CAMERA_OPEN:  return "camera-open";
        case KASBAH_EV_MIC_OPEN:     return "mic-open";
        case KASBAH_EV_DEVICE_CLOSE: return "device-close";
        case KASBAH_EV_TAMPER:       return "tamper-alert";
        default:                     return "unknown";
    }
}

int main(int argc, char **argv)
{
    io_iterator_t iter = 0;
    kern_return_t kr;
    io_service_t service = 0;

    kr = IOServiceGetMatchingServices(kIOMainPortDefault,
            IOServiceMatching("com_kasbah_guard_KasbahGuard"), &iter);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "{\"kextd\":\"error\",\"reason\":\"IOServiceGetMatchingServices failed: 0x%x\"}\n", kr);
        return 1;
    }
    service = IOIteratorNext(iter);
    IOObjectRelease(iter);
    if (!service) {
        fprintf(stderr, "{\"kextd\":\"exit\",\"reason\":\"KasbahGuard kext not loaded — Tier 1 sentinels remain active\"}\n");
        return 0;
    }

    io_connect_t connect = 0;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (kr != KERN_SUCCESS || !connect) {
        fprintf(stderr, "{\"kextd\":\"error\",\"reason\":\"IOServiceOpen failed: 0x%x (root + entitlement required)\"}\n", kr);
        IOObjectRelease(service);
        return 1;
    }
    fprintf(stderr, "{\"kextd\":\"connected\"}\n");

    struct kasbah_event events[64];
    uint32_t lastSeen = 0;
    uint64_t tsBase = mach_absolute_time();

    for (;;) {
        size_t outSize = sizeof(events);
        kr = IOConnectCallStructMethod(connect, 0, NULL, 0, events, &outSize);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "{\"kextd\":\"error\",\"reason\":\"getEvents failed: 0x%x\"}\n", kr);
            break;
        }
        uint32_t n = outSize / sizeof(struct kasbah_event);
        for (uint32_t i = 0; i < n; i++) {
            /* Events arrive newest-first; dedupe by timestamp. */
            if (events[i].timestamp_ns <= lastSeen) continue;
            lastSeen = events[i].timestamp_ns;
            printf("{\"type\":\"%s\",\"pid\":%u,\"identity\":\"%s\",\"ts\":%llu}\n",
                   event_name(events[i].type), events[i].pid,
                   events[i].identity,
                   (unsigned long long)(events[i].timestamp_ns - tsBase));
            fflush(stdout);
        }
        sleep(1);
    }

    IOServiceClose(connect);
    IOObjectRelease(service);
    return 0;
}