package com.zm.zmbackend.filter;

import com.zm.zmbackend.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.HandlerInterceptor;


public class AuthenticationFilter implements HandlerInterceptor {

    private final UserService userService;

    public AuthenticationFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    public boolean preHandle( HttpServletRequest request,@NotNull
                              HttpServletResponse response,
                              Object handler) throws Exception {
        // Get the user ID from the session
        Long userId = (Long) request.getSession().getAttribute("currentUserId");

        // If no user ID in session, check for X-User-ID header (for backward compatibility)
        if (userId == null) {
            String userIdHeader = request.getHeader("X-User-ID");
            if (userIdHeader == null || userIdHeader.isEmpty()) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.getWriter().write("Authentication required");
                return false;
            }

            // Validate the user ID
            try {
                userId = Long.parseLong(userIdHeader);
                if (!userService.isAuthenticated(userId)) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().write("Invalid user ID");
                    return false;
                }

                // Store the user ID in session for future requests
                request.getSession().setAttribute("currentUserId", userId);
            } catch (NumberFormatException e) {
                response.setStatus(HttpStatus.BAD_REQUEST.value());
                response.getWriter().write("Invalid user ID format");
                return false;
            }
        }

        // Verify that the user is still authenticated
        if (!userService.isAuthenticated(userId)) {
            // If not authenticated, invalidate the session
            request.getSession().invalidate();
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Authentication required");
            return false;
        }

        // Set the user ID as a request attribute for controllers to use
        request.setAttribute("currentUserId", userId);
        return true;
    }
}
