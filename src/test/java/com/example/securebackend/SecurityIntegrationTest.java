package com.example.securebackend;

import com.example.securebackend.config.JwtProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    JwtProperties jwtProperties;

    private String login(String username, String password) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode json = objectMapper.readTree(body);
        return json.get("accessToken").asText();
    }

    @Test
    void publicEndpointIsAccessibleWithoutToken() throws Exception {
        mockMvc.perform(get("/api/public/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void protectedEndpointWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("AUTH_REQUIRED"));
    }

    @Test
    void loginWithValidCredentialsReturnsJwt() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user\",\"password\":\"User123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void loginWithWrongPasswordReturns401WithCustomMessage() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Usuario o contraseña incorrectos."));
    }

    @Test
    void loginWithBlankFieldsReturns400() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void protectedEndpointWithValidTokenReturns200() throws Exception {
        String token = login("user", "User123!");
        mockMvc.perform(get("/api/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("user"));
    }

    @Test
    void adminEndpointWithUserTokenReturns403() throws Exception {
        String token = login("user", "User123!");
        mockMvc.perform(get("/api/admin/dashboard").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    void adminEndpointWithAdminTokenReturns200() throws Exception {
        String token = login("admin", "Admin123!");
        mockMvc.perform(get("/api/admin/dashboard").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.admin").value("admin"));
    }

    @Test
    void garbageTokenReturns401TokenInvalid() throws Exception {
        mockMvc.perform(get("/api/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer esto.no.es-un-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_INVALID"));
    }

    @Test
    void tokenSignedWithAnotherKeyReturns401TokenInvalid() throws Exception {
        SecretKey otherKey = Keys.hmacShaKeyFor(
                "otra-clave-distinta-de-al-menos-32-bytes-de-longitud!!".getBytes());
        String forged = Jwts.builder()
                .issuer(jwtProperties.issuer())
                .subject("admin")
                .claim("roles", List.of("ROLE_ADMIN"))
                .expiration(Date.from(Instant.now().plusSeconds(600)))
                .signWith(otherKey)
                .compact();

        mockMvc.perform(get("/api/admin/dashboard").header(HttpHeaders.AUTHORIZATION, "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_INVALID"));
    }

    @Test
    void expiredTokenReturns401TokenExpired() throws Exception {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.secret()));
        String expired = Jwts.builder()
                .issuer(jwtProperties.issuer())
                .subject("user")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(Date.from(Instant.now().minusSeconds(7200)))
                .expiration(Date.from(Instant.now().minusSeconds(3600)))
                .signWith(key)
                .compact();

        mockMvc.perform(get("/api/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("TOKEN_EXPIRED"));
    }

    @Test
    void unknownRouteForAuthenticatedUserReturns404Json() throws Exception {
        String token = login("user", "User123!");
        mockMvc.perform(get("/api/no-existe").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    void corsPreflightFromAngularOriginIsAllowed() throws Exception {
        mockMvc.perform(options("/api/users/me")
                        .header(HttpHeaders.ORIGIN, "http://localhost:4200")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:4200"));
    }

    @Test
    void corsPreflightFromUnknownOriginIsRejected() throws Exception {
        mockMvc.perform(options("/api/users/me")
                        .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isForbidden());
    }
}
