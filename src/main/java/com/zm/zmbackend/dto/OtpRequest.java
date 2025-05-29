package com.zm.zmbackend.dto;

import lombok.Data;

@Data
public class OtpRequest {
    private Long userId;
    private String code;
} 