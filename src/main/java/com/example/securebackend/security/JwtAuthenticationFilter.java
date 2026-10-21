package com.example.securebackend.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Lee la cabecera {@code Authorization: Bearer <token>}, valida el JWT y, si es correcto,
 * autentica la petición. Si el token es inválido o está vencido NO responde aquí: deja el motivo
 * en un atributo de la petición y el {@link RestAuthenticationEntryPoint} responde 401 con un mensaje claro.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    static final String ERROR_ATTRIBUTE = "security.jwt.error";
    static final String ERROR_EXPIRED = "EXPIRED";
    static final String ERROR_INVALID = "INVALID";

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final SecurityAuditLogger audit;

    public JwtAuthenticationFilter(JwtService jwtService, SecurityAuditLogger audit) {
        this.jwtService = jwtService;
        this.audit = audit;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            try {
                Claims claims = jwtService.parse(token);
                var authentication = UsernamePasswordAuthenticationToken.authenticated(
                        claims.getSubject(), null, jwtService.authoritiesFrom(claims));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            } catch (ExpiredJwtException e) {
                request.setAttribute(ERROR_ATTRIBUTE, ERROR_EXPIRED);
                audit.tokenRejected("expirado", request.getRemoteAddr(), request.getRequestURI());
            } catch (JwtException | IllegalArgumentException e) {
                request.setAttribute(ERROR_ATTRIBUTE, ERROR_INVALID);
                audit.tokenRejected("inválido", request.getRemoteAddr(), request.getRequestURI());
            }
        }

        chain.doFilter(request, response);
    }
}
