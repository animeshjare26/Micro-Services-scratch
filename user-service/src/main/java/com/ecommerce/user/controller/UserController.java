package com.ecommerce.user.controller;

import com.ecommerce.user.dtos.response.UserResponseDto;
import com.ecommerce.user.security.services.UserDetailsImpl;
import com.ecommerce.user.service.UserService;
import com.ecommerce.user.util.GenericResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;


/**
 * =====================================================================================
 * FILE: UserController.java
 * MODULE: user-service
 * PURPOSE: Protected REST controller for managing authenticated user profiles.
 * <p>
 * DESIGN PATTERN: Controller Pattern with Method-Level Security (@PreAuthorize).
 * <p>
 * EXECUTION FLOW:
 * 1. Request carries Bearer JWT.
 * 2. AuthTokenFilter validates JWT and sets UserDetails in SecurityContext.
 * 3. Spring MVC injects authenticated principal via @AuthenticationPrincipal.
 * 4. Controller retrieves user details and returns GenericResponse.
 * <p>
 * TRICKY INTERVIEW QUESTIONS & ARCHITECTURAL WISDOM:
 * Q1: How does `@AuthenticationPrincipal` resolve arguments in Spring MVC?
 * A1: Spring registers an `AuthenticationPrincipalArgumentResolver`. It inspects
 * `SecurityContextHolder.getContext().getAuthentication().getPrincipal()`. If the principal's
 * runtime type matches the parameter type (`UserDetailsImpl`), Spring automatically injects it!
 * <p>
 * =====================================================================================
 * SPRING WEB & SECURITY ANNOTATIONS MASTERCLASS:
 * =====================================================================================
 * 1. @RestController vs @Controller:
 * - @Controller returns a View name (String) resolved by ViewResolvers (e.g. JSP, Thymeleaf).
 * - @RestController is a convenience meta-annotation combining @Controller + @ResponseBody.
 * Every method's return value is written directly into the HTTP response stream as JSON
 * via MappingJackson2HttpMessageConverter!
 * <p>
 * 2. @RequestMapping vs @GetMapping:
 * - @RequestMapping(method = RequestMethod.GET, path = "/me") is the generic HTTP mapping.
 * - @GetMapping("/me") is a composed shortcut annotation introduced in Spring 4.3 that
 * improves readability and eliminates boilerplate `method = RequestMethod.GET` syntax.
 * <p>
 * 3. @PathVariable vs @RequestParam:
 * - @PathVariable extracts values from the URI template path: /users/{id} -> /users/42
 * - @RequestParam extracts query parameters from the URL query string: /users?page=1&size=20
 * <p>
 * 4. @PreAuthorize vs @Secured:
 * - @Secured is a legacy Spring annotation that only accepts simple string role checks.
 * - @PreAuthorize supports full Spring Expression Language (SpEL), allowing complex boolean
 * checks like: @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")!
 * <p>
 * 5. @AuthenticationPrincipal:
 * - Automatically binds the current authenticated user's Principal from the SecurityContext
 * to the method parameter, completely eliminating manual SecurityContextHolder lookups!
 * =====================================================================================
 */

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<GenericResponse<UserResponseDto>> getCurrentUser(
            @AuthenticationPrincipal UserDetailsImpl userDetails
    ) {
        UserResponseDto response = userService.getUserById(userDetails.getId());
        return ResponseEntity.ok(GenericResponse.success(response));
    }

    @GetMapping
    public ResponseEntity<GenericResponse<List<UserResponseDto>>> getAllUsers(){

        List<UserResponseDto> users = userService.getAll();
        return ResponseEntity.ok(GenericResponse.success(users));
    }

    @GetMapping("/{id}")
    public ResponseEntity<GenericResponse<UserResponseDto>> getById(@PathVariable Long id){

        UserResponseDto response= userService.getUserById(id);
        return ResponseEntity.ok(GenericResponse.success(response));
    }
}
