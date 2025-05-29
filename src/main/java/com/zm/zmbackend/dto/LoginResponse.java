package com.zm.zmbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponse {
    private Long userId;
    private String token;
    private boolean emailVerified;
    // User's display name
    private String name;
    // User's email address
    private String email;
    // URL to the user's profile image
    private String profileImageUrl;
}
