package com.zm.zmbackend.controllers;

import com.zm.zmbackend.dto.LoginRequest;
import com.zm.zmbackend.dto.LoginResponse;
import com.zm.zmbackend.dto.VerificationRequest;
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

import java.util.Collections;

import java.util.List;
import java.util.Map;
import java.util.Optional;

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

            LoginResponse response = new LoginResponse(
                user.getId(),
                token,
                user.getEmailVerified()
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

            LoginResponse response = new LoginResponse(
                user.getId(),
                null, // No token needed with session auth
                user.getEmailVerified()
            );

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user, HttpServletRequest request) {
        try {
            // Check if email already exists
            Optional<User> existingUser = userService.getUserByEmail(user.getEmail());
            if (existingUser.isPresent()) {
                return new ResponseEntity<>("Email already in use", HttpStatus.CONFLICT);
            }

            // Set email verification status to false
            user.setEmailVerified(false);

            User savedUser = userService.createUser(user);

            // Create authentication object
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                savedUser.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

            // Set details
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // Store user ID in session
            request.getSession().setAttribute("currentUserId", savedUser.getId());

            LoginResponse response = new LoginResponse(
                savedUser.getId(),
                null, // No token needed with session auth
                savedUser.getEmailVerified()
            );

            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
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
