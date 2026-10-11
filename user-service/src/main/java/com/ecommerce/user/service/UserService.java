package com.ecommerce.user.service;

import com.ecommerce.user.dtos.request.SignUpRequestDto;
import com.ecommerce.user.dtos.response.UserResponseDto;

import java.util.List;

public interface UserService {
    UserResponseDto getUserById(Long id);

    List<UserResponseDto> getAll();

    UserResponseDto createuser(SignUpRequestDto signUpRequestDto);
}
