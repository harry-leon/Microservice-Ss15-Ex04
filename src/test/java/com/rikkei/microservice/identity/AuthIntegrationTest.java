package com.rikkei.microservice.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rikkei.microservice.identity.dto.LoginRequest;
import com.rikkei.microservice.identity.dto.RegisterRequest;
import com.rikkei.microservice.identity.dto.TokenRefreshRequest;
import com.rikkei.microservice.identity.entity.RefreshToken;
import com.rikkei.microservice.identity.repository.RefreshTokenRepository;
import com.rikkei.microservice.identity.repository.UserRepository;
import com.rikkei.microservice.identity.security.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void testRegisterAndLoginReturnsBothTokens() throws Exception {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("testuser")
                .email("testuser@example.com")
                .password("password123")
                .roles(Set.of("USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseContent).get("accessToken").asText();
        String refreshTokenString = objectMapper.readTree(responseContent).get("refreshToken").asText();

        // 1. Verify Access Token claims
        assertThat(jwtUtils.validateJwtToken(accessToken)).isTrue();
        assertThat(jwtUtils.getUsernameFromJwtToken(accessToken)).isEqualTo("testuser");
        io.jsonwebtoken.Claims claims = jwtUtils.getClaimsFromJwtToken(accessToken);
        assertThat(claims.getSubject()).isEqualTo("testuser");
        assertThat(claims.get("role")).isEqualTo("USER");
        assertThat(claims.getId()).isNotBlank();

        // 2. Verify Refresh Token is persisted in DB
        Optional<RefreshToken> tokenInDb = refreshTokenRepository.findByToken(refreshTokenString);
        assertThat(tokenInDb).isPresent();
        assertThat(tokenInDb.get().getUser().getUsername()).isEqualTo("testuser");
        assertThat(tokenInDb.get().getExpiryDate()).isAfter(java.time.Instant.now());
    }

    @Test
    void testTokenRotationWorkflow() throws Exception {
        // Step 1: Register and login to obtain initial tokens
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("rotationuser")
                .email("rotation@example.com")
                .password("password123")
                .roles(Set.of("USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("rotationuser")
                .password("password123")
                .build();

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponse = loginResult.getResponse().getContentAsString();
        String originalRefreshToken = objectMapper.readTree(loginResponse).get("refreshToken").asText();

        // Step 2: Call POST /api/auth/refresh with originalRefreshToken -> should return new pair of tokens
        TokenRefreshRequest refreshRequest = TokenRefreshRequest.builder()
                .refreshToken(originalRefreshToken)
                .build();

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        String refreshResponse = refreshResult.getResponse().getContentAsString();
        String newAccessToken = objectMapper.readTree(refreshResponse).get("accessToken").asText();
        String newRefreshToken = objectMapper.readTree(refreshResponse).get("refreshToken").asText();

        // Validate new tokens
        assertThat(newRefreshToken).isNotEqualTo(originalRefreshToken);
        assertThat(jwtUtils.validateJwtToken(newAccessToken)).isTrue();
        assertThat(jwtUtils.getUsernameFromJwtToken(newAccessToken)).isEqualTo("rotationuser");

        // Old refresh token must no longer exist in DB
        assertThat(refreshTokenRepository.findByToken(originalRefreshToken)).isEmpty();

        // New refresh token must exist in DB
        Optional<RefreshToken> newDbToken = refreshTokenRepository.findByToken(newRefreshToken);
        assertThat(newDbToken).isPresent();
        assertThat(newDbToken.get().getUser().getUsername()).isEqualTo("rotationuser");

        // Step 3: Call POST /api/auth/refresh again with the old (rotated) token -> System rejects with 403 Forbidden
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403));
    }
}
