package com.example.securebackend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Levanta el servidor real (Tomcat con TLS) y verifica el handshake, las versiones de protocolo
 * permitidas y la redirección HTTP -> HTTPS.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {"server.port=18443", "app.http-redirect.port=18080"})
class TlsIntegrationTest {

    private static final String HTTPS_URL = "https://localhost:18443/api/public/health";
    private static final String HTTP_URL = "http://localhost:18080/api/public/health";

    /** Cliente que confía en el certificado autofirmado del keystore de desarrollo. */
    private HttpClient clientWithProtocols(String... protocols) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (InputStream in = new ClassPathResource("keystore/devkeystore.p12").getInputStream()) {
            trust.load(in, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);

        SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(protocols);

        return HttpClient.newBuilder().sslContext(context).sslParameters(parameters).build();
    }

    private HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void handshakeWithTls13Succeeds() throws Exception {
        HttpResponse<String> response = get(clientWithProtocols("TLSv1.3"), HTTPS_URL);

        assertEquals(200, response.statusCode());
        assertEquals("TLSv1.3", response.sslSession().orElseThrow().getProtocol());
        assertTrue(response.body().contains("\"secure\":true"));
        assertTrue(response.headers().firstValue("Strict-Transport-Security").isPresent(),
                "Debe enviarse la cabecera HSTS");
    }

    @Test
    void handshakeWithTls12Succeeds() throws Exception {
        HttpResponse<String> response = get(clientWithProtocols("TLSv1.2"), HTTPS_URL);

        assertEquals(200, response.statusCode());
        assertEquals("TLSv1.2", response.sslSession().orElseThrow().getProtocol());
    }

    @Test
    void handshakeWithTls11IsRejected() throws Exception {
        HttpClient legacyClient = clientWithProtocols("TLSv1.1");

        // El handshake falla (SSLHandshakeException) o el propio cliente se niega a usar TLS 1.1
        assertThrows(Exception.class, () -> get(legacyClient, HTTPS_URL));
    }

    @Test
    void plainHttpRequestIsRedirectedToHttps() throws Exception {
        // HttpClient por defecto NO sigue redirecciones, así se puede inspeccionar la respuesta 3xx
        HttpResponse<String> response = get(HttpClient.newHttpClient(), HTTP_URL);

        assertTrue(response.statusCode() == 302 || response.statusCode() == 307 || response.statusCode() == 301,
                "Se esperaba una redirección y se obtuvo " + response.statusCode());
        String location = response.headers().firstValue("Location").orElse("");
        assertTrue(location.startsWith("https://localhost:18443/"), "Location inesperado: " + location);
    }
}
