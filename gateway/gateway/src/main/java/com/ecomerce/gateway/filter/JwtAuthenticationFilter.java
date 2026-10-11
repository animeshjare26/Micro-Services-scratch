package com.ecomerce.gateway.filter;

import com.ecomerce.gateway.security.RsaKeyProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;


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
public class JwtAuthenticationFilter {


    private final RsaKeyProvider rsaKeyProvider;
    private final ReactiveStringRedisTemplate
}
