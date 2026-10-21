package com.example.securebackend.config;

import com.example.securebackend.security.JwtAuthenticationFilter;
import com.example.securebackend.security.JwtService;
import com.example.securebackend.security.RestAccessDeniedHandler;
import com.example.securebackend.security.RestAuthenticationEntryPoint;
import com.example.securebackend.security.SecurityAuditLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtService jwtService,
                                                   SecurityAuditLogger audit,
                                                   RestAuthenticationEntryPoint authenticationEntryPoint,
                                                   RestAccessDeniedHandler accessDeniedHandler) throws Exception {

        // El filtro se crea aquí (no como @Component) para que solo se ejecute dentro de la cadena de Spring Security
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtService, audit);

        http
                .cors(Customizer.withDefaults())
                // API stateless con Bearer token en cabecera: no se usan cookies de sesión, por lo que CSRF no aplica
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()      // preflight CORS
                        .requestMatchers("/api/auth/**", "/api/public/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)   // 401
                        .accessDeniedHandler(accessDeniedHandler))             // 403
                .headers(headers -> headers
                        // Indica a los navegadores que usen siempre HTTPS (solo se emite en respuestas HTTPS)
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000)))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.security.cors.allowed-origins}") List<String> allowedOrigins) {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        configuration.setExposedHeaders(List.of("WWW-Authenticate"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
