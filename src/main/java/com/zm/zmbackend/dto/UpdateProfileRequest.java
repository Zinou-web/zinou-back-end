package com.zm.zmbackend.dto;

import lombok.Data;

/**
 * DTO for user profile updates from client.
 */
@Data
public class UpdateProfileRequest {
    private String name;
    private String email;
    private String phone;
} 