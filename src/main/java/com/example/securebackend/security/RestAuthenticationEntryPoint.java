package com.example.securebackend.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 401 Unauthorized: la petición llega sin credenciales o con un token inválido/vencido.
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ErrorResponseWriter writer;
    private final SecurityAuditLogger audit;

    public RestAuthenticationEntryPoint(ErrorResponseWriter writer, SecurityAuditLogger audit) {
        this.writer = writer;
        this.audit = audit;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        Object jwtError = request.getAttribute(JwtAuthenticationFilter.ERROR_ATTRIBUTE);

        String code;
        String message;
        if (JwtAuthenticationFilter.ERROR_EXPIRED.equals(jwtError)) {
            code = "TOKEN_EXPIRED";
            message = "El token de autenticación ha expirado. Inicie sesión nuevamente.";
        } else if (JwtAuthenticationFilter.ERROR_INVALID.equals(jwtError)) {
            code = "TOKEN_INVALID";
            message = "El token de autenticación no es válido.";
        } else {
            code = "AUTH_REQUIRED";
            message = "Se requiere autenticación. Envíe un token Bearer válido en la cabecera Authorization.";
            audit.unauthenticatedAccess(request.getRemoteAddr(), request.getMethod(), request.getRequestURI());
        }

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        writer.write(response, HttpStatus.UNAUTHORIZED, code, message, request.getRequestURI());
    }
}
