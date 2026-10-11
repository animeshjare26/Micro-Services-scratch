package com.ecommerce.user.controller;

import com.ecommerce.user.dtos.request.LoginRequestDto;
import com.ecommerce.user.dtos.request.RefreshTokenRequestDto;
import com.ecommerce.user.dtos.request.ResetPasswordRequestDto;
import com.ecommerce.user.dtos.request.SignUpRequestDto;
import com.ecommerce.user.dtos.response.LoginResponseDto;
import com.ecommerce.user.dtos.response.UserResponseDto;
import com.ecommerce.user.service.AuthService;
import com.ecommerce.user.service.UserService;
import com.ecommerce.user.util.GenericResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * =====================================================================================
 * FILE: AuthController.java
 * MODULE: user-service
 * PURPOSE: Public REST API Controller exposing user registration, login, token refresh,
 * email lookup, and password recovery.
 * <p>
 * DESIGN PATTERN: Front Controller Pattern (Spring MVC @RestController), DTO Pattern.
 * <p>
 * EXECUTION FLOW (HOW CLIENT INTERACTS WITH AUTH CONTROLLER):
 * 1. Client sends JSON payload to `http://localhost:8081/api/auth/signup`.
 * 2. Tomcat delegates to DispatcherServlet -> RequestMappingHandlerMapping.
 * 3. HandlerAdapter invokes the matched method (e.g. `signup()`).
 * 4. Jakarta Bean Validation executes on `@Valid @RequestBody`:
 * - Checks `@NotBlank`, `@Email`, `@Size`.
 * - If validation fails: throws `MethodArgumentNotValidException`, caught by `GlobalExceptionHandler`.
 * 5. Controller invokes `AuthService` interface method.
 * 6. Wraps resulting DTO in `GenericResponse.success()` and returns appropriate HTTP status code.
 * <p>
 * READING ORDER:
 * - Read PREVIOUS: AuthServiceImpl.java, GenericResponse.java
 * - Read THIS FILE: Understand the public REST endpoints and response formatting.
 * - Read NEXT: UserController.java
 * =====================================================================================
 */

@RequestMapping("/auth")
@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<GenericResponse<UserResponseDto>> signup(
            @Valid @RequestBody SignUpRequestDto signUpRequestDto
    ) {

        UserResponseDto response = authService.signUp(signUpRequestDto);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(GenericResponse.success(response, "User registered successfully."));
    }

    @PostMapping("/login")
    public ResponseEntity<GenericResponse<LoginResponseDto>> login(
            @Valid @RequestBody LoginRequestDto loginRequestDto
    ) {

        LoginResponseDto response = authService.login(loginRequestDto);

        return ResponseEntity.ok(GenericResponse.success(response, "Login successful"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<GenericResponse<String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequestDto request) {

        authService.resetPassword(request);

        return ResponseEntity.ok(GenericResponse.success("Password updated successfully", "Password reset successful"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<GenericResponse<LoginResponseDto>> refreshAccessToken(
            @Valid @RequestBody RefreshTokenRequestDto tokenRequestDto) {

        LoginResponseDto response = authService.refreshAccessToken(tokenRequestDto);

        return ResponseEntity.ok(GenericResponse.success(response, "Token refreshed successfully"));
    }

}
