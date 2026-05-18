import Capacitor
import CommonCrypto
import Foundation
import Security

struct SSLPinningConfiguration {
    let certs: [String]
    let pins: [String]
    let excludedDomains: [String]

    static let empty = SSLPinningConfiguration(certs: [], pins: [], excludedDomains: [])

    var configured: Bool {
        !certs.isEmpty || !pins.isEmpty
    }

    var asJSObject: [String: Any] {
        [
            "configured": configured,
            "certs": certs,
            "pins": pins,
            "excludedDomains": excludedDomains
        ]
    }

    static func from(_ pluginConfig: PluginConfig) -> SSLPinningConfiguration {
        let certs = (pluginConfig.getArray("certs") as? [String]) ?? []
        let pins = (pluginConfig.getArray("pins") as? [String]) ?? []
        let excludedDomains = (pluginConfig.getArray("excludedDomains") as? [String]) ?? []
        return SSLPinningConfiguration(certs: certs, pins: pins, excludedDomains: excludedDomains)
    }
}

enum SSLPinningMatcher {
    static func isExcluded(url: URL, excludedDomains: [String]) -> Bool {
        for rawValue in excludedDomains where !rawValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard let excludedURL = URL(string: rawValue) else {
                if url.absoluteString.hasPrefix(rawValue) {
                    return true
                }
                continue
            }

            guard excludedURL.scheme?.caseInsensitiveCompare(url.scheme ?? "") == .orderedSame else {
                continue
            }
            guard excludedURL.host?.caseInsensitiveCompare(url.host ?? "") == .orderedSame else {
                continue
            }

            let excludedPort = excludedURL.port ?? excludedURL.defaultPort
            let requestPort = url.port ?? url.defaultPort
            guard excludedPort == requestPort else {
                continue
            }

            let excludedPath = excludedURL.path
            if excludedPath.isEmpty || excludedPath == "/" {
                return true
            }

            if url.path.hasPrefix(excludedPath) {
                return true
            }
        }

        return false
    }
}

final class SSLPinningCertificateStore {
    static let shared = SSLPinningCertificateStore()

    private var cachedPaths: [String] = []
    private var cachedCertificates: [SecCertificate] = []

    private init() {}

    func certificates(for configuredPaths: [String]) throws -> [SecCertificate] {
        if configuredPaths == cachedPaths {
            return cachedCertificates
        }

        let loadedCertificates = try configuredPaths.map(loadCertificate)
        cachedPaths = configuredPaths
        cachedCertificates = loadedCertificates
        return loadedCertificates
    }

    private func loadCertificate(from configuredPath: String) throws -> SecCertificate {
        let fileName = URL(fileURLWithPath: configuredPath).lastPathComponent
        guard let resourceURL = Bundle.main.resourceURL?.appendingPathComponent("public/certs/\(fileName)"),
              let certificateData = try? Data(contentsOf: resourceURL),
              let certificate = SecCertificateCreateWithData(nil, certificateData as CFData)
        else {
            throw NSError(
                domain: "SSLPinning",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Missing bundled certificate \(fileName)"]
            )
        }

        return certificate
    }
}

enum SSLPinningTrustEvaluator {
    static func evaluate(
        challenge: URLAuthenticationChallenge,
        configuration: SSLPinningConfiguration
    ) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            return (.performDefaultHandling, nil)
        }

        if let url = url(from: challenge.protectionSpace),
           SSLPinningMatcher.isExcluded(url: url, excludedDomains: configuration.excludedDomains) {
            return (.performDefaultHandling, nil)
        }

        if configuration.certs.isEmpty && configuration.pins.isEmpty {
            return (.performDefaultHandling, nil)
        }

        if configuration.certs.isEmpty && !configuration.pins.isEmpty {
            guard let certificateChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leafCertificate = certificateChain.first,
                  verifySha256Pins(certificate: leafCertificate, pins: configuration.pins)
            else {
                return (.cancelAuthenticationChallenge, nil)
            }
            return (.useCredential, URLCredential(trust: trust))
        }

        if configuration.pins.isEmpty && !configuration.certs.isEmpty {
            do {
                let certificates = try SSLPinningCertificateStore.shared.certificates(for: configuration.certs)
                SecTrustSetAnchorCertificates(trust, certificates as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, true)

                var evaluationError: CFError?
                guard SecTrustEvaluateWithError(trust, &evaluationError) else {
                    return (.cancelAuthenticationChallenge, nil)
                }
                return (.useCredential, URLCredential(trust: trust))
            } catch {
                return (.cancelAuthenticationChallenge, nil)
            }
        }

        do {
            let certificates = try SSLPinningCertificateStore.shared.certificates(for: configuration.certs)
            SecTrustSetAnchorCertificates(trust, certificates as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)

            var evaluationError: CFError?
            guard SecTrustEvaluateWithError(trust, &evaluationError) else {
                return (.cancelAuthenticationChallenge, nil)
            }

            guard let certificateChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leafCertificate = certificateChain.first,
                  verifySha256Pins(certificate: leafCertificate, pins: configuration.pins)
            else {
                return (.cancelAuthenticationChallenge, nil)
            }

            return (.useCredential, URLCredential(trust: trust))
        } catch {
            return (.cancelAuthenticationChallenge, nil)
        }
    }

    private static func verifySha256Pins(certificate: SecCertificate, pins: [String]) -> Bool {
        guard let spkiHash = publicKeySpkiSha256(certificate: certificate) else {
            return false
        }

        let computedHash = spkiHash.base64EncodedString()

        for pin in pins {
            let expectedHash: String
            if pin.hasPrefix("sha256/") {
                expectedHash = String(pin.dropFirst(7))
            } else {
                expectedHash = pin
            }

            if computedHash == expectedHash {
                return true
            }
        }

        return false
    }

    private static func publicKeySpkiSha256(certificate: SecCertificate) -> Data? {
        guard let publicKey = SecCertificateCopyKey(certificate) else { return nil }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }

        let keyType = (SecKeyCopyAttributes(publicKey) as? [String: Any])?[kSecAttrKeyType as String] as? String

        var spki: Data
        if keyType == kSecAttrKeyTypeRSA as String {
            spki = buildRsaSpki(publicKeyData: publicKeyData)
        } else {
            spki = buildEcSpki(publicKeyData: publicKeyData, publicKey: publicKey)
        }

        return sha256(spki)
    }

    private static func buildRsaSpki(publicKeyData: Data) -> Data {
        let algorithmIdentifier: [UInt8] = [
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00
        ]

        var bitStringPayload = Data()
        bitStringPayload.append(0x00 as UInt8)
        bitStringPayload.append(publicKeyData)

        let bitString = asn1Tag(0x03, payload: bitStringPayload)

        var spkiPayload = Data(algorithmIdentifier)
        spkiPayload.append(bitString)

        return asn1Tag(0x30, payload: spkiPayload)
    }

    private static func buildEcSpki(publicKeyData: Data, publicKey: SecKey) -> Data {
        guard let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int else {
            return Data()
        }

        let curveOid: [UInt8]
        switch keySize {
        case 256:
            curveOid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        case 384:
            curveOid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        default:
            curveOid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        }

        let algorithmIdentifier: [UInt8] = [
            0x30, 0x0a + UInt8(curveOid.count - 2),
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
        ] + curveOid

        var bitStringPayload = Data()
        bitStringPayload.append(0x00 as UInt8)
        bitStringPayload.append(publicKeyData)

        let bitString = asn1Tag(0x03, payload: bitStringPayload)

        var spkiPayload = Data(algorithmIdentifier)
        spkiPayload.append(bitString)

        return asn1Tag(0x30, payload: spkiPayload)
    }

    private static func asn1Tag(_ tag: UInt8, payload: Data) -> Data {
        var result = Data([tag])
        result.append(contentsOf: derLength(payload.count))
        result.append(payload)
        return result
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var bytes = [UInt8]()
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    private static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &hash)
        }
        return Data(hash)
    }

    private static func url(from protectionSpace: URLProtectionSpace) -> URL? {
        guard let host = protectionSpace.host.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) else {
            return nil
        }
        let scheme = (protectionSpace.protocol ?? "https").lowercased()
        let port = protectionSpace.port > 0 ? ":\(protectionSpace.port)" : ""
        return URL(string: "\(scheme)://\(host)\(port)")
    }
}

final class SSLPinningURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    private let configuration: SSLPinningConfiguration
    private let disableRedirects: Bool

    init(configuration: SSLPinningConfiguration, disableRedirects: Bool) {
        self.configuration = configuration
        self.disableRedirects = disableRedirects
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let result = SSLPinningTrustEvaluator.evaluate(challenge: challenge, configuration: configuration)
        completionHandler(result.0, result.1)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(disableRedirects ? nil : request)
    }
}

private extension URL {
    var defaultPort: Int? {
        switch scheme?.lowercased() {
        case "http":
            return 80
        case "https":
            return 443
        default:
            return nil
        }
    }
}

private struct SSLPinningRequestOptions {
    let call: CAPPluginCall
    let configuration: SSLPinningConfiguration
    let config: InstanceConfiguration?
    let httpMethod: String?
    let urlString: String
    let method: String
    let params: [String: Any]
    let responseType: String
    let timeoutMs: Double
    let shouldEncodeUrlParams: Bool
    let dataType: String
    let disableRedirects: Bool
    let headers: [String: Any]

    static func make(
        from payload: NSDictionary
    ) throws -> SSLPinningRequestOptions? {
        guard let call = payload["call"] as? CAPPluginCall else {
            return nil
        }

        let httpMethod = payload["httpMethod"] as? String
        let config = payload["config"] as? InstanceConfiguration
        let configuration = config.map { SSLPinningConfiguration.from($0.getPluginConfig("SSLPinning")) } ?? .empty

        guard configuration.configured else {
            try HttpRequestHandler.request(call, httpMethod, config)
            return nil
        }

        guard var urlString = call.getString("url") else {
            throw URLError(.badURL)
        }
        if urlString == urlString.removingPercentEncoding {
            guard let encodedUrlString = urlString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
                throw URLError(.badURL)
            }
            urlString = encodedUrlString
        }

        guard let rawURL = URL(string: urlString) else {
            throw URLError(.badURL)
        }
        if SSLPinningMatcher.isExcluded(url: rawURL, excludedDomains: configuration.excludedDomains) {
            try HttpRequestHandler.request(call, httpMethod, config)
            return nil
        }

        var headers = (call.getObject("headers") ?? [:]) as [String: Any]
        if let userAgentString = config?.overridenUserAgentString,
           headers["User-Agent"] == nil,
           headers["user-agent"] == nil {
            headers["User-Agent"] = userAgentString
        }

        return SSLPinningRequestOptions(
            call: call,
            configuration: configuration,
            config: config,
            httpMethod: httpMethod,
            urlString: urlString,
            method: httpMethod ?? call.getString("method", "GET"),
            params: (call.getObject("params") ?? [:]) as [String: Any],
            responseType: call.getString("responseType") ?? "text",
            timeoutMs: call.getDouble("connectTimeout") ?? call.getDouble("readTimeout") ?? 600000.0,
            shouldEncodeUrlParams: call.getBool("shouldEncodeUrlParams", true),
            dataType: call.getString("dataType") ?? "any",
            disableRedirects: call.getBool("disableRedirects") ?? false,
            headers: headers
        )
    }
}

@objc(SSLPinningHttpRequestHandlerClass)
public final class SSLPinningHttpRequestHandlerClass: NSObject {
    @objc public static func request(_ payload: NSDictionary) {
        do {
            guard let options = try SSLPinningRequestOptions.make(from: payload) else {
                return
            }

            let requestBuilder = try buildRequest(options: options)
            let delegate = SSLPinningURLSessionDelegate(configuration: options.configuration, disableRedirects: options.disableRedirects)
            let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
            let task = session.dataTask(with: requestBuilder.getUrlRequest()) { data, response, error in
                session.invalidateAndCancel()

                if let error {
                    options.call.reject(error.localizedDescription, (error as NSError).domain, error, nil)
                    return
                }

                guard let httpResponse = response as? HTTPURLResponse else {
                    options.call.reject("Missing HTTP response")
                    return
                }

                HttpRequestHandler.setCookiesFromResponse(httpResponse, options.config)
                let resolvedResponseType = ResponseType(rawValue: options.responseType) ?? .default
                options.call.resolve(HttpRequestHandler.buildResponse(data, httpResponse, responseType: resolvedResponseType))
            }

            task.resume()
        } catch {
            let call = payload["call"] as? CAPPluginCall
            call?.reject(error.localizedDescription, (error as NSError).domain, error, nil)
        }
    }

    private static func buildRequest(options: SSLPinningRequestOptions) throws -> CapacitorUrlRequest {
        let requestBuilder = try HttpRequestHandler.CapacitorHttpRequestBuilder()
            .setUrl(options.urlString)
            .setMethod(options.method)
            .setUrlParams(options.params, options.shouldEncodeUrlParams)
            .openConnection()
            .build()

        requestBuilder.setRequestHeaders(options.headers)
        requestBuilder.setTimeout(options.timeoutMs / 1000.0)

        if let data = options.call.options["data"] as? JSValue {
            try requestBuilder.setRequestBody(data, options.dataType)
        }

        return requestBuilder
    }
}
