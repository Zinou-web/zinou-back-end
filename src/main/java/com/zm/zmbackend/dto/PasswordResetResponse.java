package com.zm.zmbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PasswordResetResponse {
    private boolean success;
    private String message;
} 