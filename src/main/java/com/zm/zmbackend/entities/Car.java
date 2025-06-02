package com.zm.zmbackend.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

@Getter
@Setter
@Entity
@Table(name = "car")
public class Car {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "Car_ID", nullable = false)
    private Long id;

    @Size(max = 255)
    @NotNull
    @Column(name = "License_plate", nullable = false, unique = true)
    private String licensePlate;

    @NotNull
    @Lob
    @Column(name = "Description", nullable = false)
    private String description;

    @Size(max = 255)
    @NotNull
    @Column(name = "Picture", nullable = false)
    private String picture;

    @Size(max = 255)
    @NotNull
    @Column(name = "Brand", nullable = false)
    private String brand;

    @NotNull
    @ColumnDefault("'Mint'")
    @Lob
    @Column(name = "car_condition", nullable = false)
    private String condition;

    @Size(max = 255)
    @NotNull
    @Column(name = "Model", nullable = false)
    private String model;

    @ColumnDefault("'0'")
    @Column(name = "Mileage", nullable = false)
    private Long mileage;

    @NotNull
    @ColumnDefault("'Hatchback'")
    @Lob
    @Column(name = "car_type", nullable = false)
    private String type;

    @Column(name = "car_year", nullable = false)
    private Long year;

    @Size(max = 255)
    @NotNull
    @Column(name = "Colour", nullable = false)
    private String colour;

    @NotNull
    @ColumnDefault("'Manual'")
    @Lob
    @Column(name = "Transmission", nullable = false)
    private String transmission;

    @NotNull
    @ColumnDefault("'Petrol'")
    @Lob
    @Column(name = "Fuel", nullable = false)
    private String fuel;

    @ColumnDefault("'4'")
    @Column(name = "Seating_capacity", nullable = false)
    private Long seatingCapacity;

    @NotNull
    @Column(name = "Rental_price_per_day", nullable = false, precision = 8, scale = 2)
    private BigDecimal rentalPricePerDay;

    @Column(name = "Rental_price_per_hour", precision = 8, scale = 2)
    private BigDecimal rentalPricePerHour;

    @NotNull
    @ColumnDefault("'Available'")
    @Lob
    @Column(name = "Rental_status", nullable = false)
    private String rentalStatus;

    @Size(max = 255)
    @NotNull
    @Column(name = "Current_location", nullable = false)
    private String currentLocation;

    @Column(name = "Last_service_date")
    private LocalDate lastServiceDate;

    @NotNull
    @Column(name = "Next_service_date", nullable = false)
    private LocalDate nextServiceDate;

    @NotNull
    @Column(name = "Insurance_expiry_date", nullable = false)
    private LocalDate insuranceExpiryDate;

    @NotNull
    @ColumnDefault("1")
    @Column(name = "GPS_enabled", nullable = false)
    private Boolean gpsEnabled = true;

    @Column(name = "Rating", columnDefinition = "int UNSIGNED not null")
    private Long rating;

    @NotNull
    @Column(name = "Created_at", nullable = false)
    private Instant createdAt;

    @NotNull
    @Column(name = "Updated_at", nullable = false)
    private Instant updatedAt;

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
