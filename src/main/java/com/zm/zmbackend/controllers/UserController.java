package com.zm.zmbackend.controllers;

import com.zm.zmbackend.dto.LoginRequest;
import com.zm.zmbackend.dto.LoginResponse;
import com.zm.zmbackend.dto.VerificationRequest;
import com.zm.zmbackend.entities.Car;
import com.zm.zmbackend.entities.Reservation;
import com.zm.zmbackend.entities.User;
import com.zm.zmbackend.services.UserService;
import com.zm.zmbackend.dto.RegisterRequest;
import com.zm.zmbackend.dto.OtpRequest;
import com.zm.zmbackend.dto.ResendOtpRequest;
import com.zm.zmbackend.services.OtpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.zm.zmbackend.dto.ImageUploadResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zm.zmbackend.dto.AddressDto;
import com.zm.zmbackend.dto.DrivingLicenseDto;
import com.zm.zmbackend.services.FavouriteService;
import com.zm.zmbackend.services.CarService;
import com.zm.zmbackend.entities.Favourite;
import com.zm.zmbackend.entities.FavouriteId;

import java.util.Collections;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final OtpService otpService;
    private final FavouriteService favouriteService;
    private final CarService carService;

    @Autowired
    public UserController(UserService userService, OtpService otpService, FavouriteService favouriteService, CarService carService) {
        this.userService = userService;
        this.otpService = otpService;
        this.favouriteService = favouriteService;
        this.carService = carService;
    }

    // Authentication endpoints

    @GetMapping("/oauth2/redirect")
    public ResponseEntity<?> handleOAuth2Redirect(@RequestParam String token, @RequestParam Long userId, HttpServletRequest request) {
        try {
            Optional<User> userOpt = userService.getUserById(userId);
            if (userOpt.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userOpt.get();
            // Ensure session is created and user ID is stored
            request.getSession().setAttribute("currentUserId", user.getId());


            LoginResponse response = new LoginResponse(
                user.getId(),
                token, // This is the OAuth token
                user.getEmailVerified(),
                user.getFirstName() + " " + user.getLastName(),
                user.getEmail(),
                user.getPicture()
            );

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/oauth2/check-email")
    public ResponseEntity<?> checkEmailExists(@RequestParam String email) {
        try {
            Optional<User> userOpt = userService.getUserByEmail(email);
            boolean exists = userOpt.isPresent();

            return new ResponseEntity<>(Map.of("exists", exists), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        try {
            Optional<User> userOpt = userService.getUserByEmail(loginRequest.getEmail());
            if (userOpt.isEmpty() || !userService.verifyPassword(loginRequest.getPassword(), userOpt.get().getPassword())) {
                return new ResponseEntity<>("Invalid email or password", HttpStatus.UNAUTHORIZED);
            }

            User user = userOpt.get();

            // Create authentication object
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

            // Set details
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // Store user ID in session and get session ID
            request.getSession().setAttribute("currentUserId", user.getId());
            String sessionId = request.getSession().getId();

            LoginResponse response = new LoginResponse(
                user.getId(),
                sessionId, // Use session ID as token
                user.getEmailVerified(),
                user.getFirstName() + " " + user.getLastName(),
                user.getEmail(),
                user.getPicture()
            );

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@RequestBody RegisterRequest registerRequest, HttpServletRequest request) {
        try {
            Optional<User> existingUser = userService.getUserByEmail(registerRequest.getEmail());
            if (existingUser.isPresent()) {
                return new ResponseEntity<>(HttpStatus.CONFLICT);
            }

            // Map DTO to entity
            User newUser = new User();
            newUser.setFirstName(registerRequest.getFirstName());
            newUser.setLastName(registerRequest.getLastName());
            newUser.setEmail(registerRequest.getEmail());
            newUser.setPhoneNumber(registerRequest.getPhone());
            newUser.setPassword(registerRequest.getPassword());
            newUser.setEmailVerified(false);
            newUser.setPhoneVerified(false);

            User savedUser = userService.createUser(newUser);

            // Establish session and return LoginResponse
            request.getSession().setAttribute("currentUserId", savedUser.getId());
            String sessionId = request.getSession().getId();
            LoginResponse response = new LoginResponse(
                savedUser.getId(),
                sessionId,
                savedUser.getEmailVerified(),
                savedUser.getFirstName() + " " + savedUser.getLastName(),
                savedUser.getEmail(),
                savedUser.getPicture()
            );
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest otpRequest) {
        boolean valid = otpService.validateOtp(otpRequest.getUserId(), otpRequest.getCode());
        if (!valid) {
            return new ResponseEntity<>(Map.of("message", "Invalid OTP"), HttpStatus.BAD_REQUEST);
        }
        Optional<User> userOpt = userService.getUserById(otpRequest.getUserId());
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setEmailVerified(true);
            userService.updateUser(user.getId(), user, user.getId());
        }
        return new ResponseEntity<>(Map.of("message", "verification_success"), HttpStatus.OK);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody ResendOtpRequest resendRequest) {
        otpService.generateOtp(resendRequest.getUserId());
        return new ResponseEntity<>(Map.of("message", "otp_sent"), HttpStatus.OK);
    }

    @PostMapping("/{userId}/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(
        @PathVariable Long userId,
        @RequestParam("code") String code,
        HttpServletRequest httpRequest) {
        try {
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null || !currentUserId.equals(userId)) {
                return new ResponseEntity<>(Map.of("message", "Unauthorized"), HttpStatus.UNAUTHORIZED);
            }
            boolean verified = userService.verifyEmail(userId, code);
            if (!verified) {
                return new ResponseEntity<>(Map.of("message", "Invalid verification code"), HttpStatus.BAD_REQUEST);
            }
            return new ResponseEntity<>(Map.of("message", "verification_success"), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Phone verification endpoint removed as per requirements

    // User management endpoints

    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/paged")
    public ResponseEntity<Page<User>> getAllUsersPaged(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sort,
            @RequestParam(defaultValue = "asc") String direction,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) Boolean emailVerified,
            @RequestParam(required = false) Boolean phoneVerified) {

        Sort.Direction sortDirection = direction.equalsIgnoreCase("desc") ? Sort.Direction.DESC : Sort.Direction.ASC;
        Pageable pageable = PageRequest.of(page, size, Sort.by(sortDirection, sort));

        // For now, we'll just use the basic pagination since we haven't implemented filtered queries in UserService
        // In a real implementation, we would add methods to UserService and UserRepo for filtered queries
        Page<User> users = userService.getAllUsersPaged(pageable);

        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id, HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            // Authorization check: users can only view their own profile
            if (!id.equals(currentUserId)) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }

            Optional<User> user = userService.getUserById(id);
            return user.map(value -> new ResponseEntity<>(value, HttpStatus.OK))
                    .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User savedUser = userService.createUser(user);
        return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody User user, 
                                          HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            User updatedUser = userService.updateUser(id, user, currentUserId);
            return new ResponseEntity<>(updatedUser, HttpStatus.OK);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id, HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            userService.deleteUser(id, currentUserId);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    // Car browsing endpoints

    @GetMapping("/cars")
    public ResponseEntity<List<Car>> getAllAvailableCars() {
        List<Car> cars = userService.getAllAvailableCars();
        return new ResponseEntity<>(cars, HttpStatus.OK);
    }

    @GetMapping("/cars/brand/{brand}")
    public ResponseEntity<List<Car>> getCarsByBrand(@PathVariable String brand) {
        List<Car> cars = userService.getCarsByBrand(brand);
        return new ResponseEntity<>(cars, HttpStatus.OK);
    }

    @GetMapping("/cars/model/{model}")
    public ResponseEntity<List<Car>> getCarsByModel(@PathVariable String model) {
        List<Car> cars = userService.getCarsByModel(model);
        return new ResponseEntity<>(cars, HttpStatus.OK);
    }

    @GetMapping("/cars/rating")
    public ResponseEntity<List<Car>> getCarsByRatingRange(@RequestParam Long minRating, @RequestParam Long maxRating) {
        List<Car> cars = userService.getCarsByRatingRange(minRating, maxRating);
        return new ResponseEntity<>(cars, HttpStatus.OK);
    }

    // Reservation management endpoints

    @PostMapping("/reservations")
    public ResponseEntity<?> createReservation(@RequestBody Reservation reservation, 
                                              HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
            }

            Reservation createdReservation = userService.createReservation(reservation, currentUserId);
            return new ResponseEntity<>(createdReservation, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Rate limit exceeded")) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.TOO_MANY_REQUESTS);
            } else if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
            } else if (e.getMessage().contains("overlapping")) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
            }
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/reservations/{id}/cancel")
    public ResponseEntity<?> cancelReservation(@PathVariable Long id, HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
            }

            Reservation cancelledReservation = userService.cancelReservation(id, currentUserId);
            return new ResponseEntity<>(cancelledReservation, HttpStatus.OK);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
            }
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/{userId}/reservations/upcoming")
    public ResponseEntity<List<Reservation>> getUpcomingReservations(@PathVariable Long userId, 
                                                                    HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            List<Reservation> reservations = userService.getUpcomingReservations(userId, currentUserId);
            return new ResponseEntity<>(reservations, HttpStatus.OK);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/{userId}/reservations/past")
    public ResponseEntity<List<Reservation>> getPastReservations(@PathVariable Long userId, 
                                                               HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            List<Reservation> reservations = userService.getPastReservations(userId, currentUserId);
            return new ResponseEntity<>(reservations, HttpStatus.OK);
        } catch (RuntimeException e) {
            if (e.getMessage().contains("Unauthorized")) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Invalidate session
            request.getSession().invalidate();

            // Clear SecurityContext
            SecurityContextHolder.clearContext();

            return ResponseEntity.ok().body(Map.of("message", "Logout successful"));
        } catch (IllegalStateException e) {
            // Session already invalidated or other issue
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("message", "Error during logout: " + e.getMessage()));
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", "Error during logout: " + e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Get current authenticated user
    @GetMapping("/me")
    public ResponseEntity<LoginResponse> getCurrentUser(HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(currentUserId);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        String sessionId = request.getSession().getId();
        LoginResponse resp = new LoginResponse(
            user.getId(),
            sessionId,
            user.getEmailVerified(),
            user.getFirstName() + " " + user.getLastName(),
            user.getEmail(),
            user.getPicture()
        );
        return new ResponseEntity<>(resp, HttpStatus.OK);
    }

    // Password Reset: request OTP
    @PostMapping("/password-reset/request")
    public ResponseEntity<Void> requestPasswordReset(@RequestParam("email") String email) {
        Optional<User> userOpt = userService.getUserByEmail(email);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        otpService.generateOtp(userOpt.get().getId());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    // Password Reset: verify OTP and set new password
    @PostMapping("/password-reset/verify")
    public ResponseEntity<com.zm.zmbackend.dto.PasswordResetResponse> verifyPasswordReset(
            @RequestParam("email") String email,
            @RequestParam("code") String code,
            @RequestParam("newPassword") String newPassword) {
        Optional<User> userOpt = userService.getUserByEmail(email);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(false, "User not found"), HttpStatus.NOT_FOUND);
        }
        Long userId = userOpt.get().getId();
        boolean valid = otpService.validateOtp(userId, code);
        if (!valid) {
            return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(false, "Invalid OTP"), HttpStatus.BAD_REQUEST);
        }
        User user = userOpt.get();
        user.setPassword(newPassword);
        userService.updateUser(userId, user, userId);
        return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(true, "Password reset successful"), HttpStatus.OK);
    }

    // Change password for authenticated user
    @PostMapping("/me/change-password")
    public ResponseEntity<com.zm.zmbackend.dto.PasswordResetResponse> changePassword(
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            HttpServletRequest request) {
        Long userId = (Long) request.getSession().getAttribute("currentUserId");
        if (userId == null) {
            return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(false, "Unauthorized"), HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(userId);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(false, "User not found"), HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        if (!userService.verifyPassword(currentPassword, user.getPassword())) {
            return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(false, "Current password incorrect"), HttpStatus.BAD_REQUEST);
        }
        user.setPassword(newPassword);
        userService.updateUser(userId, user, userId);
        return new ResponseEntity<>(new com.zm.zmbackend.dto.PasswordResetResponse(true, "Password changed successfully"), HttpStatus.OK);
    }

    // Upload profile image
    @PostMapping("/me/avatar")
    public ResponseEntity<ImageUploadResponse> uploadProfileImage(
            @RequestPart("image") MultipartFile image,
            HttpServletRequest request) {
        Long userId = (Long) request.getSession().getAttribute("currentUserId");
        if (userId == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(userId);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        // In a real app, save the file to storage and generate a URL
        String filename = image.getOriginalFilename();
        String url = "/uploads/" + filename;
        User user = userOpt.get();
        user.setPicture(url);
        userService.updateUser(userId, user, userId);
        ImageUploadResponse resp = new ImageUploadResponse(url, true, "Image uploaded");
        return new ResponseEntity<>(resp, HttpStatus.OK);
    }

    // Address Management
    @PutMapping("/{id}/address")
    public ResponseEntity<AddressDto> updateAddress(@PathVariable Long id, @RequestBody AddressDto addressDto, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(addressDto);
            user.setAddress(json);
            userService.updateUser(id, user, id);
            return new ResponseEntity<>(addressDto, HttpStatus.OK);
        } catch (JsonProcessingException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{id}/address")
    public ResponseEntity<AddressDto> getAddress(@PathVariable Long id, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        try {
            ObjectMapper mapper = new ObjectMapper();
            AddressDto dto = mapper.readValue(user.getAddress(), AddressDto.class);
            return new ResponseEntity<>(dto, HttpStatus.OK);
        } catch (JsonProcessingException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Driving License Management
    @PutMapping("/{id}/driving-license")
    public ResponseEntity<DrivingLicenseDto> updateDrivingLicense(@PathVariable Long id, @RequestBody DrivingLicenseDto dto, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(dto);
            user.setDrivingLicense(json);
            userService.updateUser(id, user, id);
            return new ResponseEntity<>(dto, HttpStatus.OK);
        } catch (JsonProcessingException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{id}/driving-license")
    public ResponseEntity<DrivingLicenseDto> getDrivingLicense(@PathVariable Long id, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        try {
            ObjectMapper mapper = new ObjectMapper();
            DrivingLicenseDto dto = mapper.readValue(user.getDrivingLicense(), DrivingLicenseDto.class);
            return new ResponseEntity<>(dto, HttpStatus.OK);
        } catch (JsonProcessingException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{id}/driving-license/image")
    public ResponseEntity<ImageUploadResponse> uploadDrivingLicenseImage(@PathVariable Long id, @RequestPart("image") MultipartFile image, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        try {
            ObjectMapper mapper = new ObjectMapper();
            DrivingLicenseDto dto;
            if (user.getDrivingLicense() != null) {
                dto = mapper.readValue(user.getDrivingLicense(), DrivingLicenseDto.class);
            } else {
                dto = new DrivingLicenseDto();
            }
            String filename = image.getOriginalFilename();
            String url = "/uploads/" + filename;
            dto.setLicenseImage(url);
            String json = mapper.writeValueAsString(dto);
            user.setDrivingLicense(json);
            userService.updateUser(id, user, id);
            ImageUploadResponse resp = new ImageUploadResponse(url, true, "License image uploaded");
            return new ResponseEntity<>(resp, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Favorites Management
    @GetMapping("/{id}/favorites")
    public ResponseEntity<List<Long>> getFavorites(@PathVariable Long id, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        List<Favourite> favs = favouriteService.getAllFavourites();
        List<Long> carIds = favs.stream()
                .filter(f -> f.getId().getUserId().equals(id))
                .map(f -> f.getId().getCarId())
                .collect(Collectors.toList());
        return new ResponseEntity<>(carIds, HttpStatus.OK);
    }

    @PostMapping("/{id}/favorites/{carId}")
    public ResponseEntity<List<Long>> addToFavorites(@PathVariable Long id, @PathVariable Long carId, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(id);
        Optional<Car> carOpt = carService.getCarById(carId);
        if (userOpt.isEmpty() || carOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Favourite fav = new Favourite();
        FavouriteId fid = new FavouriteId();
        fid.setUserId(id);
        fid.setCarId(carId);
        fav.setId(fid);
        fav.setUser(userOpt.get());
        fav.setCar(carOpt.get());
        favouriteService.createFavourite(fav);
        return getFavorites(id, request);
    }

    @DeleteMapping("/{id}/favorites/{carId}")
    public ResponseEntity<List<Long>> removeFromFavorites(@PathVariable Long id, @PathVariable Long carId, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(id)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        favouriteService.deleteFavourite(id, carId);
        return getFavorites(id, request);
    }
}
