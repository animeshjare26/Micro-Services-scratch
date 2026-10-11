package com.ecommerce.user.service;

import com.ecommerce.user.dtos.request.LoginRequestDto;
import com.ecommerce.user.dtos.request.RefreshTokenRequestDto;
import com.ecommerce.user.dtos.request.ResetPasswordRequestDto;
import com.ecommerce.user.dtos.request.SignUpRequestDto;
import com.ecommerce.user.dtos.response.LoginResponseDto;
import com.ecommerce.user.dtos.response.UserResponseDto;
import jakarta.validation.Valid;

public interface AuthService {
    UserResponseDto signUp(@Valid SignUpRequestDto signUpRequestDto);

    LoginResponseDto login(@Valid LoginRequestDto loginRequestDto);

    void resetPassword(@Valid ResetPasswordRequestDto request);

    LoginResponseDto refreshAccessToken(@Valid RefreshTokenRequestDto tokenRequestDto);
}
