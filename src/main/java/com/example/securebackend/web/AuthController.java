package com.example.securebackend.web;

import com.example.securebackend.security.JwtService;
import com.example.securebackend.security.SecurityAuditLogger;
import com.example.securebackend.web.dto.LoginRequest;
import com.example.securebackend.web.dto.LoginResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecurityAuditLogger audit;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, SecurityAuditLogger audit) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.audit = audit;
    }

    /**
     * Autentica con usuario/contraseña y devuelve un JWT.
     * Credenciales incorrectas => 401 (lo traduce {@link GlobalExceptionHandler}).
     */
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password()));

        UserDetails user = (UserDetails) authentication.getPrincipal();
        String token = jwtService.generateToken(user);
        audit.loginSuccess(user.getUsername(), http.getRemoteAddr());

        return new LoginResponse(
                token,
                "Bearer",
                jwtService.expirationSeconds(),
                user.getUsername(),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }
}
