package com.example.securebackend.web;

import com.example.securebackend.security.SecurityAuditLogger;
import com.example.securebackend.web.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Traduce excepciones lanzadas dentro de los controladores a respuestas JSON uniformes.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final SecurityAuditLogger audit;

    public GlobalExceptionHandler(SecurityAuditLogger audit) {
        this.audit = audit;
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> badCredentials(BadCredentialsException ex, HttpServletRequest request) {
        audit.loginFailure("credenciales incorrectas", request.getRemoteAddr(), request.getRequestURI());
        return unauthorized("BAD_CREDENTIALS", "Usuario o contraseña incorrectos.", request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> authentication(AuthenticationException ex, HttpServletRequest request) {
        audit.loginFailure(ex.getClass().getSimpleName(), request.getRemoteAddr(), request.getRequestURI());
        return unauthorized("AUTHENTICATION_FAILED", "No fue posible autenticar la petición.", request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> accessDenied(AccessDeniedException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.of(
                HttpStatus.FORBIDDEN, "ACCESS_DENIED",
                "No tiene permisos suficientes para acceder a este recurso.", request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> validation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return ResponseEntity.badRequest().body(ErrorResponse.of(
                HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message, request.getRequestURI()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> unreadable(HttpMessageNotReadableException ex, HttpServletRequest request) {
        return ResponseEntity.badRequest().body(ErrorResponse.of(
                HttpStatus.BAD_REQUEST, "MALFORMED_REQUEST", "El cuerpo de la petición no es un JSON válido.",
                request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> unexpected(Exception ex, HttpServletRequest request) {
        // Excepciones estándar de Spring MVC (404 ruta inexistente, 405, 415, ...) conservan su código HTTP
        if (ex instanceof org.springframework.web.ErrorResponse springError) {
            HttpStatus status = HttpStatus.valueOf(springError.getStatusCode().value());
            return ResponseEntity.status(status).body(ErrorResponse.of(
                    status, "REQUEST_ERROR", status.getReasonPhrase(), request.getRequestURI()));
        }
        log.error("Error inesperado en {}", request.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Error interno del servidor.",
                request.getRequestURI()));
    }

    private ResponseEntity<ErrorResponse> unauthorized(String code, String message, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .body(ErrorResponse.of(HttpStatus.UNAUTHORIZED, code, message, request.getRequestURI()));
    }
}
