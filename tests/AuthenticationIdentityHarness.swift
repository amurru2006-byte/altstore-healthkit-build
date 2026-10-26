// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic doubles only: no networking, account, OTP, certificate, or device inputs.
import Foundation

final class ALTAppleAPI {
    static let shared = ALTAppleAPI()
    var authenticationUserAgent: String?
    var userAgent: String { self.authenticationUserAgent ?? "akd/1.0 CFNetwork/808.1.4" }
}
struct SyntheticAnisetteData {
    let machineID: String
    let oneTimePassword: String
    let routingInfo: UInt64
}
struct SyntheticClientInfo { let userAgent: String }
final class SyntheticProvider {
    var headers: Result<(String, String, UInt64), Error> = .success(("SYNTHETIC_MACHINE_A", "SYNTHETIC_OTP_A", 7))
    var fetchCount = 0
    var inputsPreserved = false
    func fetchHeaders(from serverURL: URL, identity: String, adiPB: Data, sim: String?) async throws -> (String, String, UInt64) {
        fetchCount += 1
        inputsPreserved = serverURL.absoluteString == "https://provider.invalid" &&
            identity == "SYNTHETIC_IDENTITY" && adiPB == Data([1, 2, 3]) && sim == nil
        return try headers.get()
    }
    func fetch(userAgent: String) async throws -> SyntheticAnisetteData {
        let serverURL = URL(string: "https://provider.invalid")!
        let identity = "SYNTHETIC_IDENTITY"
        let adiPB = Data([1, 2, 3])
        let sim: String? = nil
        let response = SyntheticClientInfo(userAgent: userAgent)
        // INJECT_PRODUCTION_AUTHENTICATION_IDENTITY_PATH
        return SyntheticAnisetteData(machineID: machineID, oneTimePassword: oneTimePassword, routingInfo: routingInfo)
    }
}

@main
struct AuthenticationIdentityHarness {
    static func main() async {
        var checks = 0
        var failures = 0
        func check(_ value: Bool, _ name: String) {
            checks += 1
            if !value { failures += 1; print("FAIL: \(name)") }
        }
        let api = ALTAppleAPI.shared
        let provider = SyntheticProvider()
        let macUserAgent = "SYNTHETIC_Mac_AuthKit/1 CFNetwork/123"
        let windowsUserAgent = "SYNTHETIC_Windows_AuthKit/1 CFNetwork/456"
        api.authenticationUserAgent = nil
        check(api.userAgent == "akd/1.0 CFNetwork/808.1.4", "Optional nil retains AltSign fallback")
        do {
            let first = try await provider.fetch(userAgent: macUserAgent)
            check(api.authenticationUserAgent == macUserAgent, "Provider user agent passed through exactly")
            check(api.userAgent == macUserAgent, "Request resolver uses provider identity")
            check(first.machineID == "SYNTHETIC_MACHINE_A" && first.oneTimePassword == "SYNTHETIC_OTP_A" && first.routingInfo == 7,
                  "Provider headers remain unchanged")
            check(provider.inputsPreserved, "Existing transport inputs remain unchanged")
            provider.headers = .success(("SYNTHETIC_MACHINE_B", "SYNTHETIC_OTP_B", 8))
            let second = try await provider.fetch(userAgent: windowsUserAgent)
            check(api.authenticationUserAgent == windowsUserAgent, "Changed provider updates user agent")
            check(api.userAgent == windowsUserAgent, "Request resolver follows changed provider")
            check(second.machineID == "SYNTHETIC_MACHINE_B" && second.oneTimePassword == "SYNTHETIC_OTP_B" && second.routingInfo == 8,
                  "Changed provider data remains fresh")
            check(provider.fetchCount == 2, "Each successful request fetches headers")
            let originalError = NSError(domain: "SyntheticHeadersFailure", code: 42)
            provider.headers = .failure(originalError)
            var failedData: SyntheticAnisetteData?
            var receivedError: Error?
            do { failedData = try await provider.fetch(userAgent: "SYNTHETIC_REJECTED_IDENTITY") }
            catch { receivedError = error }
            check((receivedError as NSError?) === originalError, "Original provider error propagates")
            check(failedData == nil, "Provider failure cannot return stale data as success")
            check(api.authenticationUserAgent == windowsUserAgent, "Failed fetch cannot publish a new identity")
            check(provider.fetchCount == 3, "Failure is one provider request without a hidden retry")
            api.authenticationUserAgent = nil
            check(api.userAgent == "akd/1.0 CFNetwork/808.1.4", "Cleared optional identity retains fallback")
            provider.headers = .success(("SYNTHETIC_MACHINE_C", "SYNTHETIC_OTP_C", 9))
            let recovered = try await provider.fetch(userAgent: macUserAgent)
            check(api.authenticationUserAgent == macUserAgent && api.userAgent == macUserAgent,
                  "Successful recovery replaces optional fallback")
            check(recovered.machineID == "SYNTHETIC_MACHINE_C" && recovered.oneTimePassword == "SYNTHETIC_OTP_C" &&
                  recovered.routingInfo == 9 && provider.fetchCount == 4,
                  "Recovery returns only newly fetched data")
        } catch {
            failures += 1
            print("FAIL: Unexpected synthetic fetch error")
        }
        print("Authentication identity checks: \(checks); failures: \(failures)")
        exit(failures == 0 && checks == 16 ? 0 : 1)
    }
}
