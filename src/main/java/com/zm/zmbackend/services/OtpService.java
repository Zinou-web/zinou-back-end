package com.zm.zmbackend.services;

import com.zm.zmbackend.entities.OtpVerification;
import com.zm.zmbackend.repositories.OtpVerificationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.Duration;
import java.util.Optional;
import java.util.Random;

@Service
public class OtpService {
    private final OtpVerificationRepository otpRepo;
    private final Random random = new Random();

    @Autowired
    public OtpService(OtpVerificationRepository otpRepo) {
        this.otpRepo = otpRepo;
    }

    public OtpVerification generateOtp(Long userId) {
        String code = String.format("%06d", random.nextInt(1000000));
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofMinutes(10));
        OtpVerification otp = new OtpVerification();
        otp.setUserId(userId);
        otp.setCode(code);
        otp.setCreatedAt(now);
        otp.setExpiresAt(expiresAt);
        return otpRepo.save(otp);
    }

    public boolean validateOtp(Long userId, String code) {
        Optional<OtpVerification> otpOpt = otpRepo.findTopByUserIdOrderByCreatedAtDesc(userId);
        if (otpOpt.isEmpty()) {
            return false;
        }
        OtpVerification otp = otpOpt.get();
        if (otp.getExpiresAt().isBefore(Instant.now())) {
            return false;
        }
        return otp.getCode().equals(code);
    }
} 