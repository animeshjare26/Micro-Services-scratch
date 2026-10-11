package com.ecommerce.user.dtos.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {

    private Long id;
    private String name;
    private String email;
    private String mobileNo;
    private String profileUrl;
    private List<String> roles;

    // Populated during signup to provide immediate session tokens
    private String accessToken;
    private String refreshToken;
}
