package com.example.securebackend.web.dto;

import org.springframework.http.HttpStatus;

import java.time.Instant;

/**
 * Cuerpo JSON uniforme para todos los errores del API.
 *
 * @param code código de error estable para que el frontend pueda reaccionar (p. ej. TOKEN_EXPIRED)
 */
public record ErrorResponse(Instant timestamp, int status, String error, String code, String message, String path) {

    public static ErrorResponse of(HttpStatus status, String code, String message, String path) {
        return new ErrorResponse(Instant.now(), status.value(), status.getReasonPhrase(), code, message, path);
    }
}
