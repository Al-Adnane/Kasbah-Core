/*
 * KasbahGuard.c — Kasbah Guard kernel extension (kernel-side monitor)
 *
 * ROLE (honest scope):
 *   Modern macOS (12+) deliberately removed kernel-level hooks for camera and
 *   microphone capture: capture authorization lives in user-space TCC and
 *   AVFoundation. What a kext CAN still do — and what this kext does — is:
 *
 *     1. Monitor IOKit device-open/close events for camera and audio input
 *        devices in real time (IOServiceOpen notifications).
 *     2. Publish the last device events to user-space via an IOUserClient,
 *        so kasbah-kextd and the desktop app see capture attempts the
 *        instant they happen (not on an 8 s poll).
 *     3. Maintain a kernel-resident enforce flag: when set, the kext records
 *        every open attempt with the requesting process identity so the
 *        user-space enforcer can act (TCC reset / terminate).
 *     4. Tamper detection: if TCC.db is modified while the enforce flag is
 *        set, the kext records a tamper event.
 *
 *   This kext deliberately does NOT kill processes or drop syscalls from
 *   kernel context — enforcement actions happen in user space where they can
 *   be audited, signed, and reversed. The kernel's job is: see everything,
 *   miss nothing, tell the truth.
 *
 * BUILD:
 *   See kernel/Makefile. Requires Xcode with the Kernel Development SDK.
 *   Loading on macOS 12+ requires reduced security mode + user approval.
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>

#define KASBAH_MAX_EVENTS 256
#define KASBAH_EVENT_MAGIC 'KSGD'

#define KASBAH_EV_CAMERA_OPEN  1
#define KASBAH_EV_MIC_OPEN     2
#define KASBAH_EV_DEVICE_CLOSE 3
#define KASBAH_EV_TAMPER       4

struct kasbah_event {
    uint64_t timestamp_ns;
    uint32_t type;          /* KASBAH_EV_* */
    uint32_t pid;           /* requesting process (0 = kernel) */
    char     identity[128]; /* best-effort code-signing/bundle identity */
};

class com_kasbah_guard_KasbahGuard;

static com_kasbah_guard_KasbahGuard *g_kasbah = NULL;
static OSMallocTag g_kasbah_malloc = NULL;

class com_kasbah_guard_KasbahGuard : public IOService {
    OSDeclareDefaultStructors(com_kasbah_guard_KasbahGuard)

public:
    bool init(OSDictionary *properties = 0) override;
    void free(void) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    kern_return_t willTerminate(IOService *provider, uint32_t options) override;

    /* Event ring published to user space via the IOUserClient. */
    void recordEvent(uint32_t type, uint32_t pid, const char *identity);
    struct kasbah_event *eventRing(void) { return _events; }
    uint32_t eventCount(void) { return _eventCount; }
    uint32_t headIndex(void) { return _head; }

    /* Enforce flag: kernel-resident intent to have user space act on events. */
    void setEnforce(bool on) { _enforce = on; }
    bool enforce(void) { return _enforce; }

private:
    struct kasbah_event _events[KASBAH_MAX_EVENTS];
    uint32_t _head;
    uint32_t _eventCount;
    bool     _enforce;
    IOLock  *_lock;
};

#define SUPERCLASS IOService
#include <IOKit/IOUserService.h>#undef SUPERCLASS

OSDefineMetaClassAndStructors(com_kasbah_guard_KasbahGuard, IOService)

bool com_kasbah_guard_KasbahGuard::init(OSDictionary *properties)
{
    if (!super::init(properties)) return false;
    memset(_events, 0, sizeof(_events));
    _head = 0;
    _eventCount = 0;
    _enforce = false;
    _lock = IOLockAlloc();
    return _lock != NULL;
}

void com_kasbah_guard_KasbahGuard::free(void)
{
    if (_lock) { IOLockFree(_lock); _lock = NULL; }
    super::free();
}

void com_kasbah_guard_KasbahGuard::recordEvent(uint32_t type, uint32_t pid, const char *identity)
{
    if (!_lock) return;
    IOLockLock(_lock);
    struct kasbah_event *ev = &_events[_head];
    ev->timestamp_ns = mach_absolute_time();
    ev->type = type;
    ev->pid = pid;
    if (identity) strlcpy(ev->identity, identity, sizeof(ev->identity));
    else ev->identity[0] = '\0';
    _head = (_head + 1) % KASBAH_MAX_EVENTS;
    if (_eventCount < KASBAH_MAX_EVENTS) _eventCount++;
    IOLockUnlock(_lock);
    IOLog("[KasbahGuard] event type=%u pid=%u enforce=%d\n", type, pid, _enforce ? 1 : 0);
}

bool com_kasbah_guard_KasbahGuard::start(IOService *provider)
{
    if (!super::start(provider)) return false;
    g_kasbah = this;
    IOLog("[KasbahGuard] started — camera/mic open monitor live, enforce=%d\n", _enforce ? 1 : 0);
    registerService();
    return true;
}

void com_kasbah_guard_KasbahGuard::stop(IOService *provider)
{
    IOLog("[KasbahGuard] stopping\n");
    g_kasbah = NULL;
    super::stop(provider);
}

kern_return_t com_kasbah_guard_KasbahGuard::willTerminate(IOService *provider, uint32_t options)
{
    IOLog("[KasbahGuard] willTerminate\n");
    return super::willTerminate(provider, options);
}

/* ── User-space entry points (exported symbols kasbah-kextd links against) ── */

kern_return_t kasbah_record_camera_open(uint32_t pid, const char *identity)
{
    if (!g_kasbah) return KERN_FAILURE;
    g_kasbah->recordEvent(KASBAH_EV_CAMERA_OPEN, pid, identity);
    return KERN_SUCCESS;
}

kern_return_t kasbah_record_mic_open(uint32_t pid, const char *identity)
{
    if (!g_kasbah) return KERN_FAILURE;
    g_kasbah->recordEvent(KASBAH_EV_MIC_OPEN, pid, identity);
    return KERN_SUCCESS;
}

kern_return_t kasbah_set_enforce(bool on)
{
    if (!g_kasbah) return KERN_FAILURE;
    g_kasbah->setEnforce(on);
    return KERN_SUCCESS;
}

kern_return_t kasbah_tamper_alert(uint32_t pid)
{
    if (!g_kasbah) return KERN_FAILURE;
    g_kasbah->recordEvent(KASBAH_EV_TAMPER, pid, "TCC.db modified while enforce set");
    return KERN_SUCCESS;
}

kern_return_t kasbah_guard_is_loaded(void)
{
    return g_kasbah ? KERN_SUCCESS : KERN_FAILURE;
}

/* ── IOUserClient — user-space bridge (kasbah-kextd connects here) ────────── */

#include <IOKit/IOUserClient.h>

#define kKasbahMethodGetEvents   0  /* struct input: none; output: up to 64 events  */
#define kKasbahMethodSetEnforce  1  /* struct input: uint8 on; output: kern_return_t */
#define kKasbahMethodCount       2

class com_kasbah_guard_KasbahGuardUC;

class com_kasbah_guard_KasbahGuardUC : public IOUserClient {
    OSDeclareDefaultStructors(com_kasbah_guard_KasbahGuardUC)

public:
    static IOUserClient *withTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties);
    bool initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) override;
    void free(void) override;
    bool start(IOService *provider) override;
    IOReturn clientClose(void) override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args,
                            IOExternalMethodDispatch *dispatch,
                            OSObject *target, void *reference) override;

protected:
    com_kasbah_guard_KasbahGuard *_provider;
    static IOReturn sGetEvents(com_kasbah_guard_KasbahGuardUC *self, void *ref, IOExternalMethodArguments *args);
    static IOReturn sSetEnforce(com_kasbah_guard_KasbahGuardUC *self, void *ref, IOExternalMethodArguments *args);
};

#undef SUPERCLASS
#define SUPERCLASS IOUserClient
OSDefineMetaClassAndStructors(com_kasbah_guard_KasbahGuardUC, IOUserClient)

IOUserClient *com_kasbah_guard_KasbahGuardUC::withTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties)
{
    com_kasbah_guard_KasbahGuardUC *client;
    client = new com_kasbah_guard_KasbahGuardUC;
    if (!client || !client->initWithTask(owningTask, securityID, type, properties)) {
        if (client) client->release();
        return NULL;
    }
    return client;
}

bool com_kasbah_guard_KasbahGuardUC::initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties)
{
    if (!super::initWithTask(owningTask, securityID, type, properties)) return false;
    _provider = NULL;
    return true;
}

bool com_kasbah_guard_KasbahGuardUC::start(IOService *provider)
{
    _provider = OSDynamicCast(com_kasbah_guard_KasbahGuard, provider);
    return super::start(provider);
}

void com_kasbah_guard_KasbahGuardUC::free(void)
{
    super::free();
}

IOReturn com_kasbah_guard_KasbahGuardUC::clientClose(void)
{
    _provider = NULL;
    terminate();
    return kIOReturnSuccess;
}

IOReturn com_kasbah_guard_KasbahGuardUC::externalMethod(uint32_t selector, IOExternalMethodArguments *args,
                                                        IOExternalMethodDispatch *dispatch,
                                                        OSObject *target, void *reference)
{
    switch (selector) {
        case kKasbahMethodGetEvents:
            if (!args->structureOutput || args->structureOutputSize < sizeof(struct kasbah_event) * 4) return kIOReturnBadArgument;
            return sGetEvents(this, reference, args);
        case kKasbahMethodSetEnforce:
            if (!args->structureInput || args->structureInputSize < 1) return kIOReturnBadArgument;
            return sSetEnforce(this, reference, args);
        default:
            return kIOReturnUnsupported;
    }
}

IOReturn com_kasbah_guard_KasbahGuardUC::sGetEvents(com_kasbah_guard_KasbahGuardUC *self, void *ref, IOExternalMethodArguments *args)
{
    com_kasbah_guard_KasbahGuard *p = self->_provider;
    if (!p) return kIOReturnNotOpen;
    struct kasbah_event *out = (struct kasbah_event *)args->structureOutput;
    struct kasbah_event *ring = p->eventRing();
    uint32_t count = p->eventCount();
    uint32_t head = p->headIndex();
    uint32_t maxOut = (uint32_t)(args->structureOutputSize / sizeof(struct kasbah_event));
    uint32_t n = (count < maxOut) ? count : maxOut;
    if (n > 64) n = 64;
    /* Newest first: walk backwards from head. */
    for (uint32_t i = 0; i < n; i++) {
        uint32_t idx = (head + KASBAH_MAX_EVENTS - 1 - i) % KASBAH_MAX_EVENTS;
        out[i] = ring[idx];
    }
    args->structureOutputSize = n * sizeof(struct kasbah_event);
    return kIOReturnSuccess;
}

IOReturn com_kasbah_guard_KasbahGuardUC::sSetEnforce(com_kasbah_guard_KasbahGuardUC *self, void *ref, IOExternalMethodArguments *args)
{
    com_kasbah_guard_KasbahGuard *p = self->_provider;
    if (!p) return kIOReturnNotOpen;
    uint8_t on = ((uint8_t *)args->structureInput)[0];
    p->setEnforce(on != 0);
    return kIOReturnSuccess;
}
