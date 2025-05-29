package com.zm.zmbackend.repositories;

import com.zm.zmbackend.entities.OtpVerification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpVerificationRepository extends JpaRepository<OtpVerification, Long> {
    Optional<OtpVerification> findTopByUserIdOrderByCreatedAtDesc(Long userId);
} 