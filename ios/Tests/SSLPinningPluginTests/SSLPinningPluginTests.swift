import XCTest
@testable import SSLPinningPlugin

final class SSLPinningPluginTests: XCTestCase {
    func testExcludedOriginMatchesWithoutPath() {
        guard let url = URL(string: "https://analytics.google.com/collect?v=2") else {
            XCTFail("Expected valid URL")
            return
        }
        XCTAssertTrue(SSLPinningMatcher.isExcluded(url: url, excludedDomains: ["https://analytics.google.com"]))
    }

    func testExcludedPathRequiresPrefixMatch() {
        guard let allowedURL = URL(string: "https://api.example.com/v2/users"),
              let excludedURL = URL(string: "https://api.example.com/v1/users") else {
            XCTFail("Expected valid URLs")
            return
        }
        XCTAssertFalse(SSLPinningMatcher.isExcluded(url: allowedURL, excludedDomains: ["https://api.example.com/v1"]))
        XCTAssertTrue(SSLPinningMatcher.isExcluded(url: excludedURL, excludedDomains: ["https://api.example.com/v1"]))
    }
}
