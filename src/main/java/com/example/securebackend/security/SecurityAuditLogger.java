package com.example.securebackend.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Registro centralizado de eventos de seguridad (categoría de log {@code SECURITY_AUDIT}).
 * Nunca se registran contraseñas ni tokens completos.
 */
@Component
public class SecurityAuditLogger {

    private static final Logger log = LoggerFactory.getLogger("SECURITY_AUDIT");

    public void loginSuccess(String username, String ip) {
        log.info("LOGIN_OK usuario='{}' ip={}", sanitize(username), ip);
    }

    public void loginFailure(String reason, String ip, String path) {
        log.warn("LOGIN_FALLIDO motivo='{}' ip={} ruta={}", reason, ip, path);
    }

    public void tokenRejected(String reason, String ip, String path) {
        log.warn("TOKEN_RECHAZADO motivo={} ip={} ruta={}", reason, ip, path);
    }

    public void unauthenticatedAccess(String ip, String method, String path) {
        log.warn("ACCESO_NO_AUTENTICADO ip={} {} {}", ip, method, path);
    }

    public void accessDenied(String username, String ip, String method, String path) {
        log.warn("ACCESO_DENEGADO usuario='{}' ip={} {} {}", sanitize(username), ip, method, path);
    }

    /** Evita inyección de saltos de línea en los logs. */
    private static String sanitize(String value) {
        return value == null ? "-" : value.replaceAll("[\\r\\n\\t]", "_");
    }
}
