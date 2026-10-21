package com.example.securebackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Usuarios de demostración en memoria (contraseñas con BCrypt).
 * En un sistema real se sustituye por un {@code UserDetailsService} respaldado por base de datos.
 */
@Configuration
public class UserConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder encoder,
            @Value("${app.demo.admin-password:Admin123!}") String adminPassword,
            @Value("${app.demo.user-password:User123!}") String userPassword) {

        var admin = User.withUsername("admin")
                .password(encoder.encode(adminPassword))
                .roles("ADMIN", "USER")
                .build();
        var user = User.withUsername("user")
                .password(encoder.encode(userPassword))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
