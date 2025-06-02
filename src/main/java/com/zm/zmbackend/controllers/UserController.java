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
import com.zm.zmbackend.dto.ApiResponse;
import com.zm.zmbackend.dto.PasswordResetResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.beans.factory.annotation.Value;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Authentication endpoints

    @GetMapping("/oauth2/redirect")
    public ResponseEntity<ApiResponse<LoginResponse>> handleOAuth2Redirect(@RequestParam("token") String idTokenString,
                                                                           HttpServletRequest request) {
        try {
            // Verify the ID token
            NetHttpTransport transport = new NetHttpTransport();
            JacksonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                .setAudience(Collections.singletonList(googleClientId))
                .build();
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("INVALID_TOKEN", "Invalid Google ID token"));
            }
            GoogleIdToken.Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            boolean emailVerified = Boolean.TRUE.equals(payload.getEmailVerified());
            String fullName = (String) payload.get("name");
            String pictureUrl = (String) payload.get("picture");
            // Lookup or create user
            Optional<User> opt = userService.getUserByEmail(email);
            User user;
            if (opt.isPresent()) {
                user = opt.get();
            } else {
                // Auto-create new user
                User newUser = new User();
                if (fullName != null) {
                    String[] parts = fullName.split(" ", 2);
                    newUser.setFirstName(parts[0]);
                    newUser.setLastName(parts.length > 1 ? parts[1] : "");
                }
                newUser.setEmail(email);
                newUser.setEmailVerified(emailVerified);
                newUser.setPicture(pictureUrl);
                user = userService.createUser(newUser);
            }
            // Authenticate session
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                user.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
            request.getSession().setAttribute("currentUserId", user.getId());
            // Build response
            LoginResponse resp = new LoginResponse(
                user.getId(),
                idTokenString,
                emailVerified,
                user.getFirstName() + " " + user.getLastName(),
                user.getEmail(),
                user.getPicture()
            );
            return ResponseEntity.ok(ApiResponse.success(resp));
        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.failure("OAUTH_ERROR", e.getMessage()));
        }
    }

    @GetMapping("/oauth2/check-email")
    public ResponseEntity<ApiResponse<Map<String, Boolean>>> checkEmailExists(@RequestParam String email) {
        Optional<User> userOpt = userService.getUserByEmail(email);
        boolean exists = userOpt.isPresent();
        return ResponseEntity.ok(ApiResponse.success(Map.of("exists", exists)));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        try {
            Optional<User> userOpt = userService.getUserByEmail(loginRequest.getEmail());
            if (userOpt.isEmpty() || !userService.verifyPassword(loginRequest.getPassword(), userOpt.get().getPassword())) {
                return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("INVALID_CREDENTIALS", "Invalid email or password"));
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
                null,
                user.getEmailVerified(),
                user.getFirstName() + " " + user.getLastName(),
                user.getEmail(),
                user.getPicture()
            );

            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.failure("INTERNAL_ERROR", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LoginResponse>> register(@RequestBody RegisterRequest req, HttpServletRequest request) {
        try {
            Optional<User> existingUser = userService.getUserByEmail(req.getEmail());
            if (existingUser.isPresent()) {
                return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(ApiResponse.failure("EMAIL_ALREADY_IN_USE", "Email already in use"));
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
                null,
                savedUser.getEmailVerified(),
                savedUser.getFirstName() + " " + savedUser.getLastName(),
                savedUser.getEmail(),
                savedUser.getPicture()
            );

            return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success(response));
        } catch (DataIntegrityViolationException ex) {
            return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponse.failure("EMAIL_ALREADY_IN_USE", "Email already in use"));
        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.failure("INTERNAL_ERROR", e.getMessage()));
        }
    }

    // Password reset endpoints
    @PostMapping("/password-reset/request")
    public ResponseEntity<ApiResponse<Boolean>> requestPasswordReset(@RequestParam String email) {
        boolean initiated = userService.requestPasswordReset(email);
        return ResponseEntity.ok(ApiResponse.success(initiated));
    }

    @PostMapping("/password-reset/verify")
    public ResponseEntity<ApiResponse<PasswordResetResponse>> verifyPasswordReset(
            @RequestParam String email,
            @RequestParam String code,
            @RequestParam String newPassword) {
        boolean success = userService.verifyPasswordReset(email, code, newPassword);
        PasswordResetResponse result = new PasswordResetResponse(
            success,
            success ? "Password updated successfully" : "Invalid reset code"
        );
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    // Get current user profile
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<User>> getCurrentUser(HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("UNAUTHENTICATED", "User not logged in"));
        }
        Optional<User> userOpt = userService.getUserById(currentUserId);
        if (userOpt.isEmpty()) {
            return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.failure("USER_NOT_FOUND", "User not found"));
        }
        return ResponseEntity.ok(ApiResponse.success(userOpt.get()));
    }

    // Change password for current user
    @PostMapping("/me/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@RequestParam String currentPassword,
                                                            @RequestParam String newPassword,
                                                            HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("UNAUTHENTICATED", "User not logged in"));
        }
        boolean success = userService.changePassword(currentUserId, currentPassword, newPassword);
        if (!success) {
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.failure("INCORRECT_PASSWORD", "Current password is incorrect"));
        }
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    // Upload or update user avatar
    @PostMapping("/me/avatar")
    public ResponseEntity<ApiResponse<ImageUploadResponse>> uploadAvatar(@RequestPart("image") MultipartFile image,
                                                                        HttpServletRequest request) {
        Long currentUserId = (Long) request.getSession().getAttribute("currentUserId");
        if (currentUserId == null) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("UNAUTHENTICATED", "User not logged in"));
        }
        Optional<User> userOpt = userService.getUserById(currentUserId);
        if (userOpt.isEmpty()) {
            return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.failure("USER_NOT_FOUND", "User not found"));
        }
        // Simulate storing image and updating user
        String imageUrl = "/uploads/" + image.getOriginalFilename();
        ImageUploadResponse response = new ImageUploadResponse(imageUrl, true, "Avatar updated successfully");
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/{userId}/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@PathVariable Long userId,
                                                          @RequestBody VerificationRequest request) {
        boolean verified = userService.verifyEmail(userId, request.getVerificationCode());
        if (!verified) {
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.failure("INVALID_CODE", "Invalid verification code"));
        }
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    // Resend OTP endpoint
    @PostMapping("/{userId}/resend-otp")
    public ResponseEntity<ApiResponse<Void>> resendOtp(@PathVariable Long userId) {
        userService.generateEmailVerificationCode(userId);
        return ResponseEntity.ok(ApiResponse.success(null));
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
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, HttpServletResponse response) {
        // Invalidate the session and clear context
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(ApiResponse.success(null));
    }
}
