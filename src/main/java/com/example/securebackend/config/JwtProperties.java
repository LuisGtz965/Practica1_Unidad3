package com.example.securebackend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades del token JWT (prefijo {@code app.security.jwt}).
 *
 * @param secret            clave HMAC codificada en Base64 (mínimo 256 bits)
 * @param issuer            emisor (claim "iss")
 * @param expirationSeconds vigencia del token en segundos
 */
@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(String secret, String issuer, long expirationSeconds) {
}
