package com.zm.zmbackend.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String password;
} 