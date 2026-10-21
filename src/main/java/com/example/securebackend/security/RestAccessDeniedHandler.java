package com.example.securebackend.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 403 Forbidden: el usuario está autenticado pero no tiene el rol exigido.
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ErrorResponseWriter writer;
    private final SecurityAuditLogger audit;

    public RestAccessDeniedHandler(ErrorResponseWriter writer, SecurityAuditLogger audit) {
        this.writer = writer;
        this.audit = audit;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication != null ? authentication.getName() : null;
        audit.accessDenied(username, request.getRemoteAddr(), request.getMethod(), request.getRequestURI());

        writer.write(response, HttpStatus.FORBIDDEN, "ACCESS_DENIED",
                "No tiene permisos suficientes para acceder a este recurso.", request.getRequestURI());
    }
}
