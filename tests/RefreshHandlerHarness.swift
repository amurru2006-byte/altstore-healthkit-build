// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic doubles only: no networking, account, OTP, certificate, or device inputs.
import Foundation

final class ALTAnisetteData {}
typealias RefreshCompletion = (ALTAnisetteData?, Error?) -> Void
final class ALTAppleAPI {
    static let shared = ALTAppleAPI()
    var anisetteDataRefreshHandler: ((@escaping RefreshCompletion) -> Void)?
}
enum OperationError: Error, Equatable { case cancelled }
final class SyntheticContext {}
final class FetchAnisetteDataOperation {
    let context: SyntheticContext
    var resultHandler: ((Result<ALTAnisetteData, Error>) -> Void)?
    init(context: SyntheticContext) { self.context = context }
}
final class SyntheticQueue {
    var operations: [FetchAnisetteDataOperation] = []
    func addOperation(_ operation: FetchAnisetteDataOperation) { operations.append(operation) }
}
final class AuthenticationOperation {
    let context = SyntheticContext()
    let operationQueue = SyntheticQueue()
    var isCancelled = false
    var isFinished = false
    func configure() {
        // INJECT_PRODUCTION_REFRESH_BLOCK
    }
}
final class Probe {
    var count = 0
    var data: ALTAnisetteData?
    var error: Error?
    func receive(_ data: ALTAnisetteData?, _ error: Error?) {
        count += 1
        self.data = data
        self.error = error
    }
    var isCancellation: Bool { (error as? OperationError) == .cancelled }
}

var checks = 0
var failures = 0
func check(_ value: Bool, _ name: String) {
    checks += 1
    if !value { failures += 1; print("FAIL: \(name)") }
}
func request(_ probe: Probe) { ALTAppleAPI.shared.anisetteDataRefreshHandler?(probe.receive) }

let owner = AuthenticationOperation()
owner.configure()
check(ALTAppleAPI.shared.anisetteDataRefreshHandler != nil, "Production closure registered")
let first = Probe()
request(first)
check(owner.operationQueue.operations.count == 1, "A request queues one fetch")
let operation = owner.operationQueue.operations[0]
check(operation.context === owner.context, "Existing transport context preserved")
check(first.count == 0, "No cached success before fetch completes")
let fresh = ALTAnisetteData()
operation.resultHandler?(.success(fresh))
check(first.data === fresh, "New data returned unchanged")
check(first.count == 1 && first.error == nil, "Success completes without error")
let second = Probe()
request(second)
check(owner.operationQueue.operations.count == 2, "Next request performs a new fetch")
let newer = ALTAnisetteData()
owner.operationQueue.operations[1].resultHandler?(.success(newer))
check(second.count == 1 && second.data === newer && second.data !== fresh,
      "Second result does not reuse previous data")
let failed = Probe()
request(failed)
let originalError = NSError(domain: "SyntheticRefreshFailure", code: 42)
owner.operationQueue.operations[2].resultHandler?(.failure(originalError))
check((failed.error as NSError?) === originalError, "Original error propagated")
check(failed.count == 1 && failed.data == nil, "Failure never becomes cached success")

let cancelled = AuthenticationOperation()
cancelled.isCancelled = true
cancelled.configure()
let beforeCancellation = Probe()
request(beforeCancellation)
check(beforeCancellation.count == 1 && beforeCancellation.isCancellation &&
      cancelled.operationQueue.operations.isEmpty, "Cancelled owner does not queue work")

let finished = AuthenticationOperation()
finished.isFinished = true
finished.configure()
let afterFinish = Probe()
request(afterFinish)
check(afterFinish.count == 1 && afterFinish.isCancellation &&
      finished.operationQueue.operations.isEmpty, "Finished owner does not queue work")

var released: AuthenticationOperation? = AuthenticationOperation()
released?.configure()
weak var weakReleased = released
released = nil
let afterRelease = Probe()
request(afterRelease)
check(weakReleased == nil && afterRelease.count == 1 && afterRelease.isCancellation,
      "Global handler does not retain owner and completes when owner is gone")

let inflight = AuthenticationOperation()
inflight.configure()
let duringCancellation = Probe()
request(duringCancellation)
inflight.isCancelled = true
inflight.operationQueue.operations[0].resultHandler?(.success(ALTAnisetteData()))
check(duringCancellation.count == 1 && duringCancellation.isCancellation &&
      duringCancellation.data == nil, "Cancellation during fetch rejects late success")

let inflightFinish = AuthenticationOperation()
inflightFinish.configure()
let duringFinish = Probe()
request(duringFinish)
inflightFinish.isFinished = true
inflightFinish.operationQueue.operations[0].resultHandler?(.failure(originalError))
check(duringFinish.count == 1 && duringFinish.isCancellation,
      "Completion during fetch rejects stale callback")

var inflightRelease: AuthenticationOperation? = AuthenticationOperation()
inflightRelease?.configure()
let duringRelease = Probe()
request(duringRelease)
let retainedFetch = inflightRelease!.operationQueue.operations[0]
weak var weakInflight = inflightRelease
inflightRelease = nil
retainedFetch.resultHandler?(.success(ALTAnisetteData()))
check(weakInflight == nil && duringRelease.count == 1 && duringRelease.isCancellation,
      "In-flight fetch does not retain owner and reports cancellation")

let replacement = AuthenticationOperation()
replacement.configure()
let replacementProbe = Probe()
request(replacementProbe)
check(replacement.operationQueue.operations.count == 1 &&
      replacement.operationQueue.operations[0].context === replacement.context,
      "New authentication replaces old handler/context")
replacement.operationQueue.operations[0].resultHandler?(.failure(originalError))
check(replacementProbe.count == 1 && replacementProbe.data == nil &&
      (replacementProbe.error as NSError?) === originalError,
      "Replacement propagates failure without credential fallback")

print("Refresh checks: \(checks); failures: \(failures)")
exit(failures == 0 && checks == 18 ? 0 : 1)
