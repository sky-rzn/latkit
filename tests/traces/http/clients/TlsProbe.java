// SPDX-License-Identifier: GPL-2.0
// М0 reconnaissance item 4: what a stock java.net.http client negotiates over
// TLS. Java 11+ defaults to HTTP_2 with ALPN, so this is the JVM half of "how
// much of a TLS stand really goes h2".
//
//   java TlsProbe.java https://127.0.0.1:8443/hello
//
// Single-file source launch, no build step; the trust manager is deliberately
// permissive — the stand uses a self-signed certificate.
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TlsProbe {
    public static void main(String[] args) throws Exception {
        String url = args.length > 0 ? args[0] : "https://127.0.0.1:8443/hello";
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new java.security.SecureRandom());

        for (HttpClient.Version want : new HttpClient.Version[] {
                HttpClient.Version.HTTP_2, HttpClient.Version.HTTP_1_1}) {
            HttpClient client = HttpClient.newBuilder().sslContext(ctx).version(want).build();
            HttpResponse<String> r = client.send(
                    HttpRequest.newBuilder(URI.create(url)).build(),
                    HttpResponse.BodyHandlers.ofString());
            System.out.printf("java  want=%-8s got=%s status=%d%n",
                              want, r.version(), r.statusCode());
        }
    }
}
