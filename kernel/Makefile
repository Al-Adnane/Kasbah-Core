# KasbahGuard kernel extension — build system
#
# Requires:
#   - Xcode with the macOS Kernel Development SDK (xcodebuild -showsdks | grep MacOS)
#   - An Apple Developer ID + kext signing entitlement for real loading
#   - On macOS 12+: reduced security mode (csrutil disable / authenticated-root)
#     and explicit user approval in System Settings > Privacy & Security
#
# Honest note: the kext SOURCE here is complete and compiles, but a kext cannot
# be loadable on a stock modern Mac without Apple signing. That is why Kasbah
# ships a three-tier architecture:
#   Tier 1 (always on):  user-space sentinels (TCC + lsof) — observe & alert
#   Tier 2 (this kext):  kernel-side real-time event ring when signed & loaded
#   Tier 3 (enforcer):   kasbah-enforcer.js — user-space enforcement actions
# The desktop app auto-detects the highest available tier.

SDK   := $(shell xcrun --sdk macosx --show-path 2>/dev/null)
CC    := $(shell xcrun --sdk macosx --find clang 2>/dev/null)
KEXT  := KasbahGuard.kext
BUILD := build

.PHONY: all kext clean install status

all: kext

kext:
	@mkdir -p $(BUILD)
	@echo "==> Building $(KEXT)"
	@if [ -z "$(SDK)" ]; then echo "Xcode macOS SDK not found — kext build requires Xcode"; exit 1; fi
	$(CC) -kernel -arch x86_64 -arch arm64e \
	  -isysroot $(SDK) \
	  -I$(SDK)/System/Library/Frameworks/Kernel.framework/Headers \
	  -c $(KEXT)/Contents/MacOS/KasbahGuard.c -o $(BUILD)/KasbahGuard.o
	$(CC) -kernel -nostdlib -arch x86_64 -arch arm64e \
	  -Xlinker -kext \
	  -isysroot $(SDK) \
	  $(BUILD)/KasbahGuard.o -o $(BUILD)/KasbahGuard
	@cp -R $(KEXT) $(BUILD)/
	@cp $(BUILD)/KasbahGuard $(BUILD)/$(KEXT)/Contents/MacOS/KasbahGuard
	@echo "==> Built $(BUILD)/$(KEXT) (unsigned — see README.md for signing)"

sign:
	@echo "==> Signing (requires Developer ID kext entitlement)"
	@codesign --force --sign "Developer ID Application: Kasbah Guard" \
	  --options runtime $(BUILD)/$(KEXT) 2>&1 || \
	  echo "Signing failed — without a Developer ID with kext entitlement, load with reduced security: kmutil install -v $(BUILD)/$(KEXT)"

install: kext
	@echo "==> Installing into the kernel (requires approval + possibly reduced security)"
	@kmutil install -v $(BUILD)/$(KEXT) 2>&1 || \
	  echo "kmutil failed — see README.md. The user-space sentinels remain fully active regardless."

kextd:
	@mkdir -p $(BUILD)
	@echo "==> Building kasbah-kextd (user-space Tier 2 bridge)"
	@if [ -z "$(SDK)" ]; then echo "Xcode macOS SDK not found — kextd build requires Xcode"; exit 1; fi
	$(CC) -arch arm64 -arch x86_64 -isysroot $(SDK) \
	  -framework IOKit -framework CoreFoundation \
	  kextd.c -o $(BUILD)/kextd
	@echo "==> Built $(BUILD)/kextd — run with: sudo $(BUILD)/kextd (after the kext is loaded)"

status:
	@echo "==> Kernel tier status"
	@kmutil --version 2>/dev/null || echo "kmutil unavailable"
	@kextstat 2>/dev/null | grep -i kasbah && echo "KasbahGuard: LOADED" || echo "KasbahGuard: not loaded (user-space sentinels active)"

clean:
	rm -rf $(BUILD)
