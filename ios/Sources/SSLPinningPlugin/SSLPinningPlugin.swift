import Capacitor
import Foundation

@objc(SSLPinningPlugin)
public class SSLPinningPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "SSLPinningPlugin"
    public let jsName = "SSLPinning"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "getConfiguration", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getPluginVersion", returnType: CAPPluginReturnPromise)
    ]

    @objc func getConfiguration(_ call: CAPPluginCall) {
        let configuration = SSLPinningConfiguration.from(getConfig())
        call.resolve(configuration.asJSObject)
    }

    @objc func getPluginVersion(_ call: CAPPluginCall) {
        call.resolve([
            "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "ios"
        ])
    }

    @objc override public func handleWKWebViewURLAuthenticationChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) -> Bool {
        let configuration = SSLPinningConfiguration.from(getConfig())
        guard configuration.configured else {
            return false
        }

        let result = SSLPinningTrustEvaluator.evaluate(challenge: challenge, configuration: configuration)
        completionHandler(result.0, result.1)
        return true
    }
}
