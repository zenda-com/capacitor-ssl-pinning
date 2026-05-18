package io.ionic.sslpinning;

import android.util.Log;
import com.getcapacitor.Bridge;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.net.URL;
import java.util.Arrays;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

@CapacitorPlugin(name = "SSLPinning")
public class SSLPinning extends Plugin {

    private static final String TAG = "SSLPinning";
    private static final Object LOCK = new Object();
    private static SSLSocketFactory cachedSocketFactory;
    private static String[] cachedCertPaths = new String[0];

    @PluginMethod
    public void getConfiguration(final PluginCall call) {
        final Bridge bridge = getBridge();
        final JSObject result = new JSObject();
        final String[] certs = CertificateLoader.getConfiguredCertPaths(bridge);
        final String[] pins = CertificateLoader.getPins(bridge);
        final String[] excludedDomains = CertificateLoader.getExcludedDomains(bridge);
        result.put("configured", certs.length > 0 || pins.length > 0);
        result.put("certs", certs);
        result.put("pins", pins);
        result.put("excludedDomains", excludedDomains);
        call.resolve(result);
    }

    @PluginMethod
    public void getPluginVersion(final PluginCall call) {
        final JSObject result = new JSObject();
        result.put("version", "android");
        call.resolve(result);
    }

    public Boolean isDomainExcluded(final Bridge bridge, final URL url) {
        return CertificateLoader.isExcluded(url, CertificateLoader.getExcludedDomains(bridge));
    }

    public SSLSocketFactory getSSLSocketFactory(final Bridge bridge) {
        final String[] certPaths = CertificateLoader.getConfiguredCertPaths(bridge);
        final String[] pins = CertificateLoader.getPins(bridge);
        if (certPaths.length == 0 && pins.length == 0) {
            return null;
        }

        synchronized (LOCK) {
            if (cachedSocketFactory != null && Arrays.equals(certPaths, cachedCertPaths)) {
                return cachedSocketFactory;
            }

            try {
                cachedSocketFactory = CertificateLoader.createSocketFactory(bridge.getContext(), certPaths, pins);
                cachedCertPaths = Arrays.copyOf(certPaths, certPaths.length);
                return cachedSocketFactory;
            } catch (Exception exception) {
                Log.e(TAG, "Failed to create SSL socket factory", exception);
                cachedSocketFactory = null;
                cachedCertPaths = new String[0];
                return null;
            }
        }
    }
}
