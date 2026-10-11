package com.ecommerce.user.service.impl;

import com.ecommerce.user.Repository.RefreshTokenRepository;
import com.ecommerce.user.Repository.UserRepository;
import com.ecommerce.user.config.JwtConfig;
import com.ecommerce.user.dtos.request.LoginRequestDto;
import com.ecommerce.user.dtos.request.RefreshTokenRequestDto;
import com.ecommerce.user.dtos.request.ResetPasswordRequestDto;
import com.ecommerce.user.dtos.request.SignUpRequestDto;
import com.ecommerce.user.dtos.response.LoginResponseDto;
import com.ecommerce.user.dtos.response.UserResponseDto;
import com.ecommerce.user.entity.RefreshToken;
import com.ecommerce.user.entity.Role;
import com.ecommerce.user.entity.User;
import com.ecommerce.user.enums.TokenType;
import com.ecommerce.user.exceptions.DataNotFoundException;
import com.ecommerce.user.exceptions.UnauthorizedException;
import com.ecommerce.user.security.jwt.JwtUtils;
import com.ecommerce.user.security.services.UserDetailsImpl;
import com.ecommerce.user.service.AuthService;
import com.ecommerce.user.service.UserService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


/**
 * =====================================================================================
 * FILE: AuthServiceImpl.java
 * MODULE: user-service
 * PURPOSE: Implements core authentication business logic: signup, login, refresh token
 * rotation, and password recovery.
 * <p>
 * DESIGN PATTERN: Service Layer Implementation Pattern, Facade Pattern.
 * <p>
 * EXECUTION FLOW (IN & OUT OF AUTHENTICATION):
 * 1. SIGNUP:
 * - Validates email doesn't exist -> Hashes password with BCrypt -> Creates User with ROLE_USER.
 * - Generates Access Token (15 min) + Refresh Token (7 days) with a unique UUID stored in a custom `id` claim.
 * - Saves Refresh Token to whitelist table in PostgreSQL -> Returns UserResponseDto with tokens.
 * <p>
 * 2. LOGIN:
 * - Calls `authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password))`.
 * - DaoAuthenticationProvider queries DB via UserDetailsService and verifies BCrypt hash.
 * - If password matches: creates new Access Token and new Refresh Token.
 * - Saves Refresh Token record in DB -> Returns LoginResponseDto.
 * <p>
 * 3. REFRESH TOKEN ROTATION (CRITICAL SECURITY MECHANISM):
 * - Validates refresh token signature via JwtUtils.
 * - Extracts the custom token identifier and looks it up in `refresh_tokens` where `is_revoked = false`.
 * - If already revoked: treats the request as a replay attempt and throws UnauthorizedException.
 * - Marks current refresh token as REVOKED (`isRevoked = true`).
 * - Issues a BRAND NEW Access Token and a BRAND NEW Refresh Token.
 * - Saves new Refresh Token to DB -> Returns rotated tokens to user.
 * =====================================================================================
 */

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final JwtConfig jwtConfig;
    private final UserRepository userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    @Override
    public UserResponseDto signUp(SignUpRequestDto signUpRequestDto) {


        UserResponseDto userResponse = userService.createuser(signUpRequestDto);

        UUID accessJti = UUID.randomUUID();
        UUID refreshJti = UUID.randomUUID();

        Map<String, Object> accessClaims = new HashMap<>();
        accessClaims.put("id", accessJti.toString());
        accessClaims.put("jti", accessJti.toString());
        accessClaims.put("userId", userResponse.getId().toString());
        accessClaims.put("roles", userResponse.getRoles());

        String accessToken = jwtUtils.generateToken(
                TokenType.ACCESS_TOKEN,
                userResponse.getEmail(),
                accessClaims);

        String refreshToken = jwtUtils.generateToken(
                TokenType.REFRESH_TOKEN,
                userResponse.getEmail(),
                Map.of("id", refreshJti.toString())
        );

        long refreshExpMinutes = jwtConfig.getTokenConfigByType(TokenType.REFRESH_TOKEN).getExpiration();

        RefreshToken tokenEntity = new RefreshToken(
                refreshJti.toString(),
                userResponse.getEmail(),
                OffsetDateTime.now().plusMinutes(refreshExpMinutes)
        );

        refreshTokenRepository.save(tokenEntity);

        userResponse.setAccessToken(accessToken);
        userResponse.setRefreshToken(refreshToken);

        return userResponse;
    }

    @Override
    @Transactional
    public LoginResponseDto login(LoginRequestDto loginRequestDto) {


        // Delegate authentication to Spring's AuthenticationManager
        // If password is wrong or user doesn't exist, this throws BadCredentialsException!
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.getEmail().toLowerCase().trim(),
                        loginRequestDto.getPassword()
                )
        );

        //Extract principal (UserDetailsImpl) from the authenticated token
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        SecurityContextHolder.getContext().setAuthentication(authentication);


        List<String> roles = userDetails.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority)
                .toList();


        UUID accessJti = UUID.randomUUID();
        UUID refreshJti = UUID.randomUUID();

        Map<String, Object> claims = new HashMap<>();
        claims.put("id", accessJti.toString());
        claims.put("jti", accessJti.toString());
        claims.put("userId", userDetails.getId().toString());
        claims.put("roles", roles);


        String accessToken = jwtUtils.generateToken(
                TokenType.ACCESS_TOKEN,
                loginRequestDto.getEmail(),
                claims);


        String refreshToken = jwtUtils.generateToken(
                TokenType.REFRESH_TOKEN,
                loginRequestDto.getEmail(),
                Map.of("id", refreshJti.toString())
        );


        long expiration = jwtConfig.getTokenConfigByType(TokenType.REFRESH_TOKEN).getExpiration();

        RefreshToken entityToken = new RefreshToken(
                refreshJti.toString(),
                userDetails.getEmail(),
                OffsetDateTime.now().plusMinutes(expiration)
        );

        refreshTokenRepository.save(entityToken);

        User user = userRepository.findByEmailIgnoreCaseAndIsActiveTrue(userDetails.getEmail())
                .orElseThrow(() -> new DataNotFoundException("User not found"));

        return LoginResponseDto.builder()
                .userId(userDetails.getId())
                .email(userDetails.getEmail())
                .name(user.getName())
                .roles(roles)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequestDto request) {

        if (jwtUtils.validateToken(TokenType.FORGOT_PASSWORD, request.getToken())) {
            throw new UnauthorizedException("Invalid or expired password reset token");
        }
        Map<String, String> claims = jwtUtils.getClaimsFromToken(TokenType.FORGOT_PASSWORD, request.getToken());

        String email = claims.get("subject");
        User user = userRepository.findByEmailIgnoreCaseAndIsActiveTrue(email)
                .orElseThrow(() -> new DataNotFoundException("User not found : " + email));

        String encodedPassword = passwordEncoder.encode(request.getNewPassword());

        userRepository.updatePassword(user.getEmail(), encodedPassword);

        // When a user resets their password, REVOKE ALL existing refresh tokens!
        // This blocks future refreshes. It does not invalidate already-issued access tokens.
        refreshTokenRepository.revokeAllByUserEmail(user.getEmail());

    }

    @Override
    @Transactional
    public LoginResponseDto refreshAccessToken(RefreshTokenRequestDto tokenRequestDto) {


        String tokenStr = tokenRequestDto.getRefreshToken();

        if (!jwtUtils.validateToken(TokenType.REFRESH_TOKEN,tokenStr)){
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        Map<String, String> claims = jwtUtils.getClaimsFromToken(TokenType.REFRESH_TOKEN, tokenStr);

        String jti = claims.get("id");
        String email = claims.get("subject");

        RefreshToken storedToken = refreshTokenRepository.findByTokenJtiAndIsRevokedFalse(jti)
                .orElseThrow(() -> new UnauthorizedException("Refresh token is revoked or already used"));

        if (storedToken.getExpiresAt().isBefore(OffsetDateTime.now())){
            storedToken.setIsRevoked(true);
            refreshTokenRepository.save(storedToken);
            throw new UnauthorizedException("Refresh token has expired");
        }

        storedToken.setIsRevoked(true);
        refreshTokenRepository.save(storedToken);


        User user = userRepository.findByEmailIgnoreCaseAndIsActiveTrue(email)
                .orElseThrow(() -> new UnauthorizedException("User not found"));


        List<String> roles = user.getRoles()
                .stream()
                .map(Role::getName)
                .toList();


        UUID newAccessJti = UUID.randomUUID();
        UUID newRefreshJti = UUID.randomUUID();

        Map<String,Object> refreshAccessClaims = new HashMap<>();
        refreshAccessClaims.put("id",newAccessJti.toString());
        refreshAccessClaims.put("jti",newAccessJti.toString());
        refreshAccessClaims.put("userId",user.getId() != null ? user.getId().toString() : "");
        refreshAccessClaims.put("roles",roles);


        String newAccessToken = jwtUtils.generateToken(
                TokenType.ACCESS_TOKEN,
                user.getEmail(),
                refreshAccessClaims
        );

        String newRefreshToken = jwtUtils.generateToken(
                TokenType.REFRESH_TOKEN,
                user.getEmail(),
                Map.of("id",newRefreshJti.toString())
        );


        long refreshExpMin = jwtConfig.getTokenConfigByType(TokenType.REFRESH_TOKEN).getExpiration();

        RefreshToken tokenEntity = new RefreshToken(
                newRefreshJti.toString(),
                user.getEmail(),
                OffsetDateTime.now().plusMinutes(refreshExpMin)
        );

        refreshTokenRepository.save(tokenEntity);

        return LoginResponseDto.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .roles(roles)
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();


    }
}
