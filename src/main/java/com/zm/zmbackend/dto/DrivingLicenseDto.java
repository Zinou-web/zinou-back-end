package com.zm.zmbackend.dto;

import lombok.Data;

@Data
public class DrivingLicenseDto {
    private String number;
    private String expiryDate;
    private String issuingCountry;
    private String licenseImage;
} 