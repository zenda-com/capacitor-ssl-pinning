package io.ionic.sslpinning;

import android.content.Context;
import android.util.Base64;
import com.getcapacitor.Bridge;
import com.getcapacitor.PluginConfig;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

final class CertificateLoader {

    private static final String CERTS_DIR = "public/certs";

    private CertificateLoader() {}

    static String[] getConfiguredCertPaths(final Bridge bridge) {
        final PluginConfig config = bridge.getConfig().getPluginConfiguration("SSLPinning");
        final String[] certs = config.getArray("certs", new String[0]);
        return certs == null ? new String[0] : certs;
    }

    static String[] getPins(final Bridge bridge) {
        final PluginConfig config = bridge.getConfig().getPluginConfiguration("SSLPinning");
        final String[] pins = config.getArray("pins", new String[0]);
        return pins == null ? new String[0] : pins;
    }

    static String[] getExcludedDomains(final Bridge bridge) {
        final PluginConfig config = bridge.getConfig().getPluginConfiguration("SSLPinning");
        final String[] excludedDomains = config.getArray("excludedDomains", new String[0]);
        return excludedDomains == null ? new String[0] : excludedDomains;
    }

    static SSLSocketFactory createSocketFactory(final Context context, final String[] configuredCertPaths, final String[] configuredPins) throws Exception {
        X509TrustManager trustManager;

        if (configuredPins.length > 0 && configuredCertPaths.length == 0) {
            trustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    if (chain == null || chain.length == 0) {
                        throw new CertificateException("No server certificate chain provided");
                    }
                    verifySha256Pins(chain[0], configuredPins);
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        } else {
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);

            if (configuredCertPaths.length > 0) {
                int index = 0;
                for (String configuredCertPath : configuredCertPaths) {
                    final X509Certificate certificate = loadCertificate(context, configuredCertPath);
                    keyStore.setCertificateEntry("sslpinning-" + index, certificate);
                    index += 1;
                }
            }

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];

            if (configuredPins.length > 0) {
                final X509TrustManager delegate = trustManager;
                final String[] pins = configuredPins;
                trustManager = new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        delegate.checkClientTrusted(chain, authType);
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        delegate.checkServerTrusted(chain, authType);
                        verifySha256Pins(chain[0], pins);
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return delegate.getAcceptedIssuers();
                    }
                };
            }
        }

        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{ trustManager }, null);
        return sslContext.getSocketFactory();
    }

    private static void verifySha256Pins(X509Certificate leafCert, String[] pins) throws CertificateException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] pubKeyDer = leafCert.getPublicKey().getEncoded();
            byte[] hash = digest.digest(pubKeyDer);
            String computedHash = Base64.encodeToString(hash, Base64.NO_WRAP);

            for (String pin : pins) {
                String expectedHash = pin;
                if (pin.startsWith("sha256/")) {
                    expectedHash = pin.substring(7);
                }
                if (computedHash.equals(expectedHash)) {
                    return;
                }
            }

            throw new CertificateException(
                "SHA-256 public key pinning check failed: server's public key hash " + computedHash +
                " does not match any configured pin"
            );
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CertificateException("SHA-256 algorithm not available", e);
        }
    }

    static boolean isExcluded(final URL requestUrl, final String[] excludedDomains) {
        for (String rawExcludedDomain : excludedDomains) {
            if (rawExcludedDomain == null || rawExcludedDomain.trim().isEmpty()) {
                continue;
            }

            try {
                final URL excludedUrl = new URL(rawExcludedDomain);
                final int excludedPort = excludedUrl.getPort() == -1 ? excludedUrl.getDefaultPort() : excludedUrl.getPort();
                final int requestPort = requestUrl.getPort() == -1 ? requestUrl.getDefaultPort() : requestUrl.getPort();

                if (!excludedUrl.getProtocol().equalsIgnoreCase(requestUrl.getProtocol())) {
                    continue;
                }
                if (!excludedUrl.getHost().equalsIgnoreCase(requestUrl.getHost())) {
                    continue;
                }
                if (excludedPort != requestPort) {
                    continue;
                }

                final String excludedPath = excludedUrl.getPath() == null ? "" : excludedUrl.getPath();
                if (excludedPath.isEmpty() || "/".equals(excludedPath)) {
                    return true;
                }

                final String requestPath = requestUrl.getPath() == null ? "" : requestUrl.getPath();
                if (requestPath.startsWith(excludedPath)) {
                    return true;
                }
            } catch (Exception ignored) {
                if (requestUrl.toString().startsWith(rawExcludedDomain)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static X509Certificate loadCertificate(final Context context, final String configuredCertPath) throws Exception {
        final String fileName = configuredCertPath.substring(configuredCertPath.lastIndexOf('/') + 1);
        try (InputStream inputStream = context.getAssets().open(CERTS_DIR + "/" + fileName)) {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }
}
