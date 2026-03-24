package io.ionic.sslpinning;

import android.content.Context;
import com.getcapacitor.Bridge;
import com.getcapacitor.PluginConfig;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

final class CertificateLoader {

    private static final String CERTS_DIR = "public/certs";

    private CertificateLoader() {}

    static String[] getConfiguredCertPaths(final Bridge bridge) {
        final PluginConfig config = bridge.getConfig().getPluginConfiguration("SSLPinning");
        final String[] certs = config.getArray("certs", new String[0]);
        return certs == null ? new String[0] : certs;
    }

    static String[] getExcludedDomains(final Bridge bridge) {
        final PluginConfig config = bridge.getConfig().getPluginConfiguration("SSLPinning");
        final String[] excludedDomains = config.getArray("excludedDomains", new String[0]);
        return excludedDomains == null ? new String[0] : excludedDomains;
    }

    static SSLSocketFactory createSocketFactory(final Context context, final String[] configuredCertPaths) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        int index = 0;
        for (String configuredCertPath : configuredCertPaths) {
            final X509Certificate certificate = loadCertificate(context, configuredCertPath);
            keyStore.setCertificateEntry("sslpinning-" + index, certificate);
            index += 1;
        }

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return sslContext.getSocketFactory();
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
