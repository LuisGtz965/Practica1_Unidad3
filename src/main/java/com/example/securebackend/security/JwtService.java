package com.example.securebackend.security;

import com.example.securebackend.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Emisión y validación de tokens JWT firmados con HMAC-SHA.
 */
@Service
public class JwtService {

    private static final String ROLES_CLAIM = "roles";

    private final JwtProperties properties;
    private final SecretKey key;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        // Lanza WeakKeyException si la clave tiene menos de 256 bits
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.secret()));
    }

    public String generateToken(UserDetails user) {
        Instant now = Instant.now();
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .issuer(properties.issuer())
                .subject(user.getUsername())
                .claim(ROLES_CLAIM, roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(properties.expirationSeconds())))
                .signWith(key)
                .compact();
    }

    /**
     * Valida firma, emisor y vigencia. Lanza {@link io.jsonwebtoken.JwtException} si el token no es válido.
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(properties.issuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public List<GrantedAuthority> authoritiesFrom(Claims claims) {
        Object raw = claims.get(ROLES_CLAIM);
        if (raw instanceof List<?> list) {
            return list.stream()
                    .map(String::valueOf)
                    .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                    .toList();
        }
        return List.of();
    }

    public long expirationSeconds() {
        return properties.expirationSeconds();
    }
}
