// SPDX-License-Identifier: AGPL-3.0-only
#import <Foundation/Foundation.h>
#import "ALTCapabilities.h"

static int checks = 0;
static int failures = 0;
static void check(BOOL condition, const char *name) {
    checks++;
    if (!condition) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", name);
    }
}

int main(void) {
    @autoreleasepool {
        check([ALTFeatureForEntitlement(@"com.apple.developer.healthkit") isEqual:@"HK421J6T7P"], "HealthKit forward mapping");
        check([ALTEntitlementForFeature(@"HK421J6T7P") isEqual:@"com.apple.developer.healthkit"], "HealthKit reverse mapping");
        check(ALTFeatureForEntitlement(@"com.apple.developer.healthkit.access") == nil, "Do not map HealthKit access arrays");
        check(ALTFeatureForEntitlement(@"com.apple.developer.healthkit.background-delivery") == nil, "Do not invent a secondary App ID feature");
        check([ALTFeatureForEntitlement(ALTEntitlementAppGroups) isEqual:ALTFeatureAppGroups], "Existing App Groups forward");
        check([ALTEntitlementForFeature(ALTFeatureAppGroups) isEqual:ALTEntitlementAppGroups], "Existing App Groups reverse");
        check([ALTFeatureForEntitlement(ALTEntitlementIncreasedMemoryLimit) isEqual:ALTFeatureIncreasedMemoryLimit], "Existing memory forward");
        check([ALTEntitlementForFeature(ALTFeatureIncreasedMemoryLimit) isEqual:ALTEntitlementIncreasedMemoryLimit], "Existing memory reverse");
        check([ALTFeatureForEntitlement(ALTEntitlementInterAppAudio) isEqual:ALTFeatureInterAppAudio], "Existing audio forward");
        check([ALTEntitlementForFeature(ALTFeatureInterAppAudio) isEqual:ALTEntitlementInterAppAudio], "Existing audio reverse");
        check(ALTFeatureForEntitlement(@"synthetic.unknown.entitlement") == nil, "Unknown entitlement stays unsupported");
        check(ALTEntitlementForFeature(@"SYNTHETIC_UNKNOWN_FEATURE") == nil, "Unknown feature stays unsupported");
        check(ALTFeatureIsLegacy(@"HK421J6T7P"), "HealthKit follows existing legacy feature registration");
        check(!ALTFeatureIsLegacy(ALTFeatureIncreasedMemoryLimit), "Modern feature registration unchanged");
    }
    printf("Checks: %d; failures: %d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
