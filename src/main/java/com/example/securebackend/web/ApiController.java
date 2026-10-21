package com.example.securebackend.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    /** Público: sirve para verificar el handshake TLS (campo "secure"). */
    @GetMapping("/public/health")
    public Map<String, Object> health(HttpServletRequest request) {
        return Map.of(
                "status", "UP",
                "secure", request.isSecure(),
                "scheme", request.getScheme(),
                "timestamp", Instant.now().toString());
    }

    /** Protegido: cualquier usuario autenticado. */
    @GetMapping("/users/me")
    public Map<String, Object> me(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        return Map.of("username", authentication.getName(), "roles", roles);
    }

    /** Protegido: solo ROLE_ADMIN (regla definida en SecurityConfig). */
    @GetMapping("/admin/dashboard")
    public Map<String, Object> adminDashboard(Authentication authentication) {
        return Map.of("message", "Panel de administración", "admin", authentication.getName());
    }
}
