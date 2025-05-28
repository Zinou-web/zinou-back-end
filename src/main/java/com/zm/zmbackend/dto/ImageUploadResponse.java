package com.zm.zmbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ImageUploadResponse {
    private String url;
    private boolean success;
    private String message;
} 