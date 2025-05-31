package com.zm.zmbackend.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;
import java.time.LocalDate;

@Getter
@Setter
@Entity
@Table(name = "user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "User_ID", nullable = false)
    private Long id;

    @Size(max = 255)
    @Column(name = "Picture")
    private String picture;

    @Size(max = 255)
    @NotNull
    @Column(name = "First_name", nullable = false)
    private String firstName;

    @Size(max = 255)
    @NotNull
    @Column(name = "Last_name", nullable = false)
    private String lastName;

    @Column(name = "Birthday")
    private LocalDate birthday;

    @Size(max = 255)
    @Column(name = "Phone_number", nullable = true)
    private String phoneNumber;

    @Lob
    @Column(name = "Address")
    private String address;

    @Size(max = 255)
    @NotNull
    @Column(name = "Email", nullable = false, unique = true)
    private String email;

    @Size(max = 255)
    @NotNull
    @Column(name = "Password", nullable = false)
    private String password;

    @NotNull
    @ColumnDefault("false")
    @Column(name = "Email_verified", nullable = false)
    private Boolean emailVerified = false;

    @NotNull
    @ColumnDefault("false")
    @Column(name = "Phone_verified", nullable = false)
    private Boolean phoneVerified = false;

    @Size(max = 255)
    @Column(name = "Auth_token")
    private String authToken;

    @Column(name = "Token_expiry")
    private Instant tokenExpiry;

    @Size(max = 255)
    @Column(name = "Email_verification_code")
    private String emailVerificationCode;

    @Size(max = 255)
    @Column(name = "Phone_verification_code")
    private String phoneVerificationCode;

    @NotNull
    @Column(name = "Created_at", nullable = false)
    private Instant createdAt;

    @NotNull
    @Column(name = "Updated_at", nullable = false)
    private Instant updatedAt;

    @Size(max = 16)
    @Column(name = "Card_number")
    private String cardNumber;

    @Size(max = 5)
    @Column(name = "Card_expiration")
    private String cardExpiration;

    @Size(max = 3)
    @Column(name = "Card_cvv")
    private String cardCvv;

    @Size(max = 255)
    @Column(name = "Provider_id")
    private String providerId;

    @Size(max = 50)
    @Column(name = "Provider_name")
    private String providerName;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}
