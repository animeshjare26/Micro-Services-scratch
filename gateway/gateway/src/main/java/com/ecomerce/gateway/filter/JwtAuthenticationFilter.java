package com.ecomerce.gateway.filter;

import com.ecomerce.gateway.security.RsaKeyProvider;
import com.ecomerce.gateway.utils.GenericResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * =====================================================================================
 * FILE: JwtAuthenticationFilter.java
 * MODULE: api-gateway (Reactive Edge Security Filter)
 *
 * WHAT DOES THIS FILTER DO AND WHY DO WE NEED IT?
 * -------------------------------------------------------------------------------------
 * In our microservices architecture, this filter acts as the single security gate at the edge.
 * Instead of forcing every downstream microservice (product-service, order-service, etc.)
 * to parse JWT tokens and manage public keys, the API Gateway verifies the token ONCE:
 *
 *   [Client Browser / Mobile App]
 *              │  (Authorization: Bearer <token>)
 *              ▼
 *     ┌──────────────────┐
 *     │   API GATEWAY    │  1. Check public whitelist (skip login, signup, catalog browse)
 *     │  (This Filter)   │  2. Verify RS256 signature in-memory using RSA Public Key (<0.1ms)
 *     │                  │  3. Check Redis: Is this token revoked/logged out?
 *     │                  │  4. Extract userId & roles -> inject into X-User-* headers
 *     └────────┬─────────┘
 *              │  (X-User-Id: 101, X-User-Roles: ROLE_SELLER)
 *              ▼
 *     ┌──────────────────┐
 *     │ Downstream Svc   │  No JWT parsing needed! Simply reads X-User-Id
 *     │ (product-service)│  via UserContext in 0.001ms.
 *     └──────────────────┘
 *
 * HOW DOES IT PREVENT SECURITY SPOOFING?
 * -------------------------------------------------------------------------------------
 * If a malicious attacker manually adds "X-User-Id: 1" in their request, this filter's
 * mutate() step OVERWRITES it with the genuine ID extracted from the verified cryptographic
 * JWT. Untrusted client headers are completely sanitized.
 *
 * EXECUTION ORDER:
 * - Runs with Order: -1 (immediately after CorrelationIdFilter, before downstream routing).
 *
 * READING ORDER:
 * - Read PREVIOUS: security/RsaKeyProvider.java
 * - Read THIS FILE: Understand non-blocking reactive security filter implementation.
 * - Read NEXT: filter/CorrelationIdFilter.java
 *
 * TRICKY INTERVIEW QUESTIONS & ARCHITECTURAL WISDOM:
 * Q1: Senior Question: Why does this filter mutate headers instead of letting downstream services
 *     validate the JWT themselves?
 * A1: Performance & Decoupling! If every microservice (`product-service`, `cart-service`,
 *     `order-service`) had to parse JWTs, check public keys, and deserialize roles, we would
 *     waste massive CPU cycles repeating the same work 5 times per request flow. By verifying
 *     ONCE at the edge and injecting trusted `X-User-Id` headers, downstream services remain
 *     completely lightweight and focus purely on domain business logic!
 *
 * Q2: Intermediate Question: How do we prevent a malicious client from forging `X-User-Id: admin`
 *     in their HTTP request header to bypass security?
 * A2: Header Sanitization! The API Gateway's `mutate()` operation OVERWRITES any existing
 *     `X-User-*` headers sent by external clients. Downstream services are placed in a private
 *     VPC network that accepts HTTP traffic ONLY from the Gateway's IP address!
 *
 * Q3: Beginner Intern Question: What does `exchange.getResponse().writeWith(...)` do in WebFlux?
 * A3: In Spring MVC, you write directly to `HttpServletResponse.getOutputStream()`.
 *     In Spring WebFlux, because Netty is non-blocking, we allocate a `DataBuffer` containing
 *     our JSON bytes and return a reactive `Mono<Void>` stream to Netty's event loop to write
 *     the bytes asynchronously to the client socket without blocking the worker thread!
 * =====================================================================================
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final RsaKeyProvider rsaKeyProvider;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Whitelist of public endpoints that bypass JWT verification
    private static final List<String> PUBLIC_WHITELIST = List.of(
            "/api/auth/signup",
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/email-exists",
            "/api/auth/public-key",
            "/actuator"
    );

    private boolean isWhitelisted(String path) {
        return PUBLIC_WHITELIST.stream().anyMatch(path::startsWith);
    }

    @Override
    public int getOrder() {
        // High priority: -1 ensures this filter executes immediately after distributed tracing
        // (CorrelationIdFilter: -2) and before routing or load balancing filters (0 and above).
        return -1;
    }

    /**
     * NON-BLOCKING EXECUTION:
     * -------------------------------------------------------------------------------------
     * Operates entirely on Netty's reactive event loop. No threads are blocked waiting for
     * database queries or cryptographic parsing. Returns Mono<Void> to signal completion.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        // 1. Allow CORS pre-flight requests to pass through untouched
        if (HttpMethod.OPTIONS.equals(method)) {
            return chain.filter(exchange);
        }

        // 2. Allow whitelisted endpoints, but sanitize external caller identity headers
        if (isWhitelisted(path)) {
            ServerHttpRequest sanitizedRequest = exchange.getRequest().mutate()
                    .headers(this::stripUntrustedIdentityHeaders)
                    .build();
            return chain.filter(exchange.mutate().request(sanitizedRequest).build());
        }

        // 3. Validate presence of Bearer Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Missing or malformed Authorization header. Use 'Bearer <token>'", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        // 4. Cryptographic RS256 token verification
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(rsaKeyProvider.getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("JWT access token expired for path [{}]: {}", path, e.getMessage());
            return onError(exchange, "JWT access token has expired. Please refresh your session", HttpStatus.UNAUTHORIZED);
        } catch (SignatureException e) {
            log.error("CRITICAL: Invalid JWT signature detected on path [{}]! Tampering suspected: {}", path, e.getMessage());
            return onError(exchange, "Invalid cryptographic token signature", HttpStatus.UNAUTHORIZED);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Malformed or invalid JWT token on path [{}]: {}", path, e.getMessage());
            return onError(exchange, "Invalid JWT authentication token", HttpStatus.UNAUTHORIZED);
        }

        // 5. Redis JTI blocklist check for revoked tokens
        // Pure stateless JWTs cannot be revoked before expiration. We solve this by storing
        // revoked token JTIs (JWT IDs) in Redis with a TTL matching token expiry.
        // If the JTI exists in "blocklist:jti:{jti}", the token is immediately rejected.
        String jti = claims.get("jti") != null ? claims.get("jti").toString() : claims.get("id", String.class);
        if (jti != null && !jti.isBlank()) {
            String blocklistKey = "blocklist:jti:" + jti;
            return redisTemplate.hasKey(blocklistKey)
                    .defaultIfEmpty(false)
                    .flatMap(isRevoked -> {
                        if (Boolean.TRUE.equals(isRevoked)) {
                            log.warn("Rejected revoked token with JTI [{}] on path [{}]", jti, path);
                            return onError(exchange, "Token has been revoked. Please log in again", HttpStatus.UNAUTHORIZED);
                        }
                        return proceedWithDownstreamHeaders(exchange, chain, claims);
                    })
                    // Resilient Fallback: If Redis is temporarily down, log error and fail-open to preserve availability
                    .onErrorResume(e -> {
                        log.error("Redis blocklist check failed for JTI [{}]: {}. Proceeding with cryptographic trust", jti, e.getMessage());
                        return proceedWithDownstreamHeaders(exchange, chain, claims);
                    });
        }

        return proceedWithDownstreamHeaders(exchange, chain, claims);
    }

    /**
     * Sanitizes external headers and injects verified cryptographic claims downstream.
     *
     * ZERO-TRUST DOWNSTREAM ENRICHMENT:
     * -------------------------------------------------------------------------------------
     * Downstream services (product-service, order-service, inventory-service) run in a private VPC.
     * They do not need to parse JWT tokens, query databases for user info, or hold RSA public keys.
     * Instead, they read these sanitized headers from UserContext in 0.001ms.
     */
    private Mono<Void> proceedWithDownstreamHeaders(ServerWebExchange exchange, GatewayFilterChain chain, Claims claims) {
        String userId = claims.get("userId") != null ? claims.get("userId").toString() : "";
        String email = claims.getSubject() != null ? claims.getSubject() : "";
        String roles = serializeRoles(claims.get("roles"));

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    // Step 1: Strip any caller-provided spoofed headers
                    stripUntrustedIdentityHeaders(headers);

                    // Step 2: Inject authenticated, gateway-attested facts
                    headers.set("X-User-Id", userId);
                    headers.set("X-User-Email", email);
                    headers.set("X-User-Roles", roles);
                })
                .build();

        log.debug("Successfully authenticated request for userId [{}], email [{}]. Mutating downstream headers", userId, email);
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String serializeRoles(Object rolesObj) {
        if (rolesObj == null) {
            return "[]";
        }
        try {
            return objectMapper.writeValueAsString(rolesObj);
        } catch (JsonProcessingException e) {
            log.warn("Failed to serialize roles object: {}", e.getMessage());
            return "[]";
        }
    }

    /**
     * Defense-in-depth: Strips every identity header a client could attempt to spoof.
     * Downstream microservices treat X-User-* headers as absolute truth, so any external
     * values must be forcibly purged before request propagation.
     */
    private void stripUntrustedIdentityHeaders(HttpHeaders headers) {
        headers.remove("X-User-Id");
        headers.remove("X-User-Email");
        headers.remove("X-User-Roles");
    }

    /**
     * REACTIVE NON-BLOCKING ERROR HANDLING:
     * -------------------------------------------------------------------------------------
     * In traditional Spring MVC (Servlet), errors write to HttpServletResponse.getOutputStream().
     * In Spring WebFlux / Project Reactor, Netty operates asynchronously. We allocate a
     * DataBuffer wrapping our serialized JSON bytes and return response.writeWith(Mono.just(buffer))
     * back to Netty's event loop, avoiding thread starvation under high load.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.empty();
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        GenericResponse<Void> errorEnvelope = GenericResponse.error(message, List.of(message));
        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(errorEnvelope);
        } catch (JsonProcessingException e) {
            bytes = ("{\"success\":false,\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
