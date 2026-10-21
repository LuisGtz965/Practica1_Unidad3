package com.example.securebackend.config;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Abre un conector HTTP secundario cuya única función es redirigir (302) cualquier
 * petición en texto plano hacia el puerto HTTPS. Nunca se atiende contenido por HTTP.
 * <p>
 * Para rechazar en lugar de redirigir, desactivar con {@code app.http-redirect.enabled=false}:
 * entonces el puerto HTTP ni siquiera se abre y las peticiones no cifradas son rechazadas.
 */
@Configuration
@ConditionalOnProperty(name = "app.http-redirect.enabled", havingValue = "true", matchIfMissing = true)
public class HttpsRedirectConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpToHttpsRedirectCustomizer(
            @Value("${app.http-redirect.port:8080}") int httpPort,
            @Value("${server.port:8443}") int httpsPort) {

        return factory -> {
            // Toda URL exige canal confidencial (CONFIDENTIAL => redirección al redirectPort)
            factory.addContextCustomizers(context -> {
                SecurityConstraint constraint = new SecurityConstraint();
                constraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                constraint.addCollection(collection);
                context.addConstraint(constraint);
            });

            Connector httpConnector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            httpConnector.setScheme("http");
            httpConnector.setPort(httpPort);
            httpConnector.setSecure(false);
            httpConnector.setRedirectPort(httpsPort);
            factory.addAdditionalTomcatConnectors(httpConnector);
        };
    }
}
