package com.ecomerce.gateway.exception;

import com.ecomerce.gateway.utils.GenericResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;


/**
 * =====================================================================================
 * FILE: GatewayExceptionHandler.java
 * MODULE: api-gateway (Global Reactive Error Handler)
 * PURPOSE: Catches all unhandled exceptions and HTTP error codes at the Gateway edge
 *          (e.g., 404 Route Not Found, 429 Rate Limit Exceeded, 503 Downstream Down)
 *          and formats them into our unified `GenericResponse<T>` JSON envelope.
 *
 * DESIGN PATTERN / SPRING MECHANISM:
 * - Reactive Exception Translation Pattern (`ErrorWebExceptionHandler`).
 * - High Priority (`order = -2`): Intercepts errors before default Spring Boot error pages.
 *
 * READING ORDER:
 * - Read PREVIOUS: config/RateLimiterConfig.java
 * - Read THIS FILE: Understand reactive error handling in Spring WebFlux.
 * - Read NEXT: ApiGatewayApplication.java
 *
 * TRICKY INTERVIEW QUESTIONS & ARCHITECTURAL WISDOM:
 * Q1: Senior Question: Why can't we use `@RestControllerAdvice` in Spring Cloud Gateway?
 * A1: `@RestControllerAdvice` belongs to Spring MVC / WebFlux annotation-driven controllers.
 *     In Spring Cloud Gateway, requests do NOT terminate in a `@RestController`.
 *     They flow through reactive filter chains and Netty channel handlers.
 *     If a downstream microservice is down (503) or rate-limiting kicks in (429), the error
 *     is produced inside Netty's reactive pipeline where only an `ErrorWebExceptionHandler`
 *     can intercept and serialize it!
 *
 * Q2: Intermediate Question: What error does Gateway throw when Eureka has 0 instances of a service?
 * A2: It throws a `ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Unable to find instance for user-service")`.
 *     Our handler catches this and translates it to a clean JSON response:
 *     `{ "success": false, "message": "Service temporarily unavailable. Please try again later." }`
 *
 * Q3: Beginner Intern Question: What happens if `response.isCommitted()` is true when an error occurs?
 * A3: If response headers or body chunks have already started streaming across the socket to the client,
 *     we CANNOT modify the status code or write a new JSON envelope! We must check `if (response.isCommitted())`
 *     and return `Mono.error(ex)` to prevent Netty buffer corruption.
 * =====================================================================================
 */

// @Component: Registers this class as a Spring Bean in the application context so Spring WebFlux auto-detects it.
// @Slf4j: Lombok annotation that injects an SLF4J Logger (log) for logging diagnostic messages.
@Component
@Slf4j
public class GatewayExceptionHandler implements ErrorWebExceptionHandler, Ordered {

    // Jackson ObjectMapper used to serialize our Java GenericResponse objects into JSON byte arrays.
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Determines the execution precedence of this error handler.
     *
     * In Spring Cloud Gateway / WebFlux:
     * - The default handler (DefaultErrorWebExceptionHandler) has an order of -1.
     * - By returning -2 (lower number = higher precedence), our custom handler executes FIRST,
     *   allowing us to intercept and format errors into our unified JSON envelope before Spring Boot
     *   falls back to its generic error page or default JSON representation.
     */
    @Override
    public int getOrder() {
        return -2;
    }

    /**
     * Core reactive error handling method called whenever an unhandled exception bubbles up
     * from any filter or route handler in the gateway pipeline.
     *
     * @param exchange The reactive HTTP request-response exchange context.
     * @param ex       The unhandled Throwable/Exception thrown during processing.
     * @return Mono<Void> indicating when error writing and response completion is finished.
     */
    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        // Extract the reactive HTTP response object to set status codes, headers, and the response body.
        ServerHttpResponse response = exchange.getResponse();

        // ---------------------------------------------------------------------------------
        // STEP 1: Guard against committed responses.
        // In reactive streaming (Netty), once headers or body chunks start transmitting across
        // the network socket to the client, the response is considered "committed".
        // Attempting to modify headers or rewrite status codes on a committed response will cause
        // Netty buffer corruption or protocol violation errors. If already committed, propagate as-is.
        // ---------------------------------------------------------------------------------
        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        // ---------------------------------------------------------------------------------
        // STEP 2: Determine appropriate HTTP Status Code and human-readable Error Message.
        // Default fallback is 500 Internal Server Error.
        // ---------------------------------------------------------------------------------
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String errorMessage = "Internal server error occurred at API Gateway";

        // Case A: Spring WebFlux ResponseStatusException
        // Triggered by Gateway filters, routing errors (e.g., 404 Route Not Found, 429 Rate Limit, 401 Unauthorized)
        if (ex instanceof ResponseStatusException rse) {
            status = HttpStatus.resolve(rse.getStatusCode().value());
            if (status == null) status = HttpStatus.INTERNAL_SERVER_ERROR;
            errorMessage = rse.getReason() != null ? rse.getReason() : rse.getMessage();

        // Case B: Service Discovery (Eureka / Consul) failure
        // Thrown when a microservice has 0 instances registered or alive in the service registry.
        } else if (ex.getMessage() != null && ex.getMessage().contains("Unable to find instance")) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            errorMessage = "Downstream service is currently unavailable. Please try again in a few moments";

        // Case C: Socket connection failure
        // Downstream microservice port is closed, process crashed, or network firewall blocked connection.
        } else if (ex.getMessage() != null && ex.getMessage().contains("Connection refused")) {
            status = HttpStatus.BAD_GATEWAY;
            errorMessage = "Failed to connect to downstream service (Connection refused)";
        }

        // ---------------------------------------------------------------------------------
        // STEP 3: Configure Response Headers.
        // Set the calculated status code and ensure Content-Type is application/json.
        // ---------------------------------------------------------------------------------
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // ---------------------------------------------------------------------------------
        // STEP 4: Build standard error payload and serialize to bytes.
        // Uses GenericResponse<T> envelope: { success: false, message: ..., errors: [...] }
        // ---------------------------------------------------------------------------------
        GenericResponse<Void> errorEnvelope = GenericResponse.error(errorMessage, List.of(errorMessage));
        byte[] bytes;
        try {
            // Attempt standard JSON serialization using Jackson
            bytes = objectMapper.writeValueAsBytes(errorEnvelope);
        } catch (JsonProcessingException e) {
            // Safe fallback: If Jackson serialization fails unexpectedly, return a minimal manual JSON payload
            // to ensure the client always receives valid JSON instead of hanging or returning raw errors.
            bytes = ("{\"success\":false,\"message\":\"" + errorMessage + "\"}").getBytes(StandardCharsets.UTF_8);
        }

        // ---------------------------------------------------------------------------------
        // STEP 5: Wrap payload in Netty reactive DataBuffer and write asynchronously.
        // - DataBuffer: WebFlux abstraction over Netty's ByteBuf (avoids redundant memory copying).
        // - writeWith(Mono.just(buffer)): Streams the buffer over the network socket and completes the Mono.
        // ---------------------------------------------------------------------------------
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
