package com.zm.zmbackend.dto;

import lombok.Data;
import com.zm.zmbackend.dto.AddressDto;

/**
 * DTO for user profile updates from client.
 */
@Data
public class UpdateProfileRequest {
    private String name;
    private String email;
    private String phone;
    // Date of birth in ISO format (e.g., YYYY-MM-DD)
    private String birthday;
    // User address details
    private AddressDto address;
} 