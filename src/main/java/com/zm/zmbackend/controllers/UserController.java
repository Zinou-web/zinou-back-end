package com.zm.zmbackend.controllers;

import com.zm.zmbackend.dto.LoginRequest;
import com.zm.zmbackend.dto.LoginResponse;
import com.zm.zmbackend.dto.VerificationRequest;
import com.zm.zmbackend.dto.UpdateProfileRequest;
import com.zm.zmbackend.dto.RegisterRequest;
import com.zm.zmbackend.entities.Car;
import com.zm.zmbackend.entities.Reservation;
import com.zm.zmbackend.entities.User;
import com.zm.zmbackend.services.UserService;
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

import java.util.Collections;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.time.LocalDate;
import com.zm.zmbackend.dto.AddressDto;
import com.zm.zmbackend.dto.ImageUploadResponse;
import org.springframework.dao.DataIntegrityViolationException;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Authentication endpoints

    @GetMapping("/oauth2/redirect")
    public ResponseEntity<?> handleOAuth2Redirect(@RequestParam String token, @RequestParam Long userId) {
        try {
            Optional<User> userOpt = userService.getUserById(userId);
            if (userOpt.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userOpt.get();

            // Include name, email, and profile image in response
            LoginResponse response = new LoginResponse(
                user.getId(),
                token,
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

            // Store user ID in session
            request.getSession().setAttribute("currentUserId", user.getId());

            // Include name, email, and profile image in response
            LoginResponse response = new LoginResponse(
                user.getId(),
                null, // No token needed with session auth
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
    public ResponseEntity<?> register(@RequestBody RegisterRequest req, HttpServletRequest request) {
        try {
            // Check if email already exists
            Optional<User> existingUser = userService.getUserByEmail(req.getEmail());
            if (existingUser.isPresent()) {
                return new ResponseEntity<>("Email already in use", HttpStatus.CONFLICT);
            }

            // Create new User entity from DTO
            User newUser = new User();
            newUser.setFirstName(req.getFirstName());
            newUser.setLastName(req.getLastName());
            newUser.setEmail(req.getEmail());
            newUser.setPassword(req.getPassword());
            newUser.setPhoneNumber(req.getPhone());
            // Other optional fields (picture, address, birthday) are left null
            newUser.setEmailVerified(false);
            User savedUser = userService.createUser(newUser);

            // Generate and send email verification code
            userService.generateEmailVerificationCode(savedUser.getId());

            // Create authentication object
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                savedUser.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

            // Set details
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // Store user ID in session
            request.getSession().setAttribute("currentUserId", savedUser.getId());

            // Include name, email, and profile image in response
            LoginResponse response = new LoginResponse(
                savedUser.getId(),
                null, // No token needed with session auth
                savedUser.getEmailVerified(),
                savedUser.getFirstName() + " " + savedUser.getLastName(),
                savedUser.getEmail(),
                savedUser.getPicture()
            );

            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (DataIntegrityViolationException ex) {
            // Handle duplicate key or constraint violations (e.g., empty or existing email)
            return new ResponseEntity<>("Email already in use", HttpStatus.CONFLICT);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Password reset endpoints
    @PostMapping("/password-reset/request")
    public ResponseEntity<?> requestPasswordReset(@RequestParam String email) {
        try {
            boolean initiated = userService.requestPasswordReset(email);
            return ResponseEntity.ok(Map.of("success", initiated));
        } catch (ResourceNotFoundException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/password-reset/verify")
    public ResponseEntity<PasswordResetResponse> verifyPasswordReset(
            @RequestParam String email,
            @RequestParam String code,
            @RequestParam String newPassword) {
        try {
            boolean success = userService.verifyPasswordReset(email, code, newPassword);
            return ResponseEntity.ok(new PasswordResetResponse(success, success ? "Password updated successfully" : "Invalid reset code"));
        } catch (ResourceNotFoundException e) {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Get current user profile
    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser(HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(currentUserId);
        return userOpt.map(user -> new ResponseEntity<>(user, HttpStatus.OK))
                      .orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    // Change password for current user
    @PostMapping("/me/change-password")
    public ResponseEntity<?> changePassword(@RequestParam String currentPassword,
                                            @RequestParam String newPassword,
                                            HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        boolean success = userService.changePassword(currentUserId, currentPassword, newPassword);
        if (!success) {
            return new ResponseEntity<>("Current password is incorrect", HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok(Map.of("success", true));
    }

    // Upload or update user avatar
    @PostMapping("/me/avatar")
    public ResponseEntity<ImageUploadResponse> uploadAvatar(@RequestPart("image") MultipartFile image,
                                                             HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Optional<User> userOpt = userService.getUserById(currentUserId);
        if (userOpt.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User user = userOpt.get();
        // In a real application, you'd save the image to cloud/storage and get a URL
        String imageUrl = "/uploads/" + image.getOriginalFilename();
        user.setPicture(imageUrl);
        userService.updateUser(currentUserId, user, currentUserId);
        return ResponseEntity.ok(new ImageUploadResponse(imageUrl, true, "Avatar updated successfully"));
    }

    @PostMapping("/{userId}/verify-email")
    public ResponseEntity<?> verifyEmail(@PathVariable Long userId, 
                                        @RequestBody VerificationRequest request,
                                        HttpServletRequest httpRequest) {
        try {
            // Get user ID from session
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null || !currentUserId.equals(userId)) {
                return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
            }

            boolean verified = userService.verifyEmail(userId, request.getVerificationCode());
            if (!verified) {
                return new ResponseEntity<>("Invalid verification code", HttpStatus.BAD_REQUEST);
            }

            return new ResponseEntity<>("Email verified successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Resend OTP endpoint
    @PostMapping("/{userId}/resend-otp")
    public ResponseEntity<?> resendOtp(@PathVariable Long userId, HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null || !currentUserId.equals(userId)) {
            return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
        }
        userService.generateEmailVerificationCode(userId);
        return new ResponseEntity<>(Map.of("message", "otp_sent"), HttpStatus.OK);
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
    public ResponseEntity<User> updateUser(@PathVariable Long id,
                                           @RequestBody UpdateProfileRequest request,
                                           HttpServletRequest httpRequest) {
        try {
            Long currentUserId = (Long) httpRequest.getSession().getAttribute("currentUserId");
            if (currentUserId == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            if (!currentUserId.equals(id)) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }
            Optional<User> existingUserOpt = userService.getUserById(id);
            if (existingUserOpt.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
            User user = existingUserOpt.get();
            if (request.getName() != null) {
                String[] parts = request.getName().split(" ", 2);
                user.setFirstName(parts[0]);
                user.setLastName(parts.length > 1 ? parts[1] : "");
            }
            if (request.getEmail() != null) {
                user.setEmail(request.getEmail());
            }
            if (request.getPhone() != null) {
                user.setPhoneNumber(request.getPhone());
            }
            // Update birthday if provided
            if (request.getBirthday() != null) {
                user.setBirthday(LocalDate.parse(request.getBirthday()));
            }
            // Update address if provided
            if (request.getAddress() != null) {
                AddressDto addr = request.getAddress();
                String fullAddress = String.join(", ",
                    addr.getStreet(), addr.getCity(), addr.getState(), addr.getZipCode(), addr.getCountry());
                user.setAddress(fullAddress);
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
            // Invalidate the session
            request.getSession().invalidate();

            // Clear authentication from security context
            SecurityContextHolder.clearContext();

            return new ResponseEntity<>("Logged out successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
