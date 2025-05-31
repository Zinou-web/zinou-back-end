package com.zm.zmbackend.config;

import com.zm.zmbackend.services.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import lombok.*;
import com.zm.zmbackend.oauth2.CustomOAuth2UserService;
import com.zm.zmbackend.oauth2.OAuth2AuthenticationSuccessHandler;
import com.zm.zmbackend.filter.SessionAuthenticationFilter;

import javax.sql.DataSource;

import java.util.Arrays;

@Getter
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final UserServiceImpl userService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final DataSource dataSource;
    private final SessionAuthenticationFilter sessionAuthenticationFilter;
    private final UserDetailsService userDetailsService;

    @Lazy
    @Autowired
    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService,
                          OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler, 
                          UserServiceImpl userService,
                          DataSource dataSource,
                          SessionAuthenticationFilter sessionAuthenticationFilter,
                          CustomUserDetailsService userDetailsService) {
        this.userService = userService;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.dataSource = dataSource;
        this.sessionAuthenticationFilter = sessionAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authenticationProvider(authenticationProvider())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )
            .authorizeHttpRequests(authorize -> authorize
                // Public endpoints
                .requestMatchers("/api/users/login", "/api/users/register", "/oauth2/**").permitAll()
                // Allow mobile clients to hit the OAuth2 redirect JSON endpoint
                .requestMatchers("/api/users/oauth2/**").permitAll()
                // Allow password reset and email verification endpoints without authentication
                .requestMatchers("/api/users/password-reset/**", "/api/users/*/verify-email", "/api/users/*/resend-otp").permitAll()
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                // Car endpoints - only GET operations are allowed for all users
                .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/cars/**").permitAll()
                // Block POST, PUT, DELETE operations on cars for regular users
                .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/cars/**").denyAll()
                .requestMatchers(org.springframework.http.HttpMethod.PUT, "/api/cars/**").denyAll()
                .requestMatchers(org.springframework.http.HttpMethod.DELETE, "/api/cars/**").denyAll()

                // User endpoints - require authentication and proper authorization
                .requestMatchers("/api/users/**").hasRole("USER")

                // Block admin access to database operations
                .requestMatchers("/api/admin/**").denyAll()
                .requestMatchers("/h2-console/**").denyAll()
                .requestMatchers("/actuator/db-metrics/**").denyAll()

                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                )
                .successHandler(oAuth2AuthenticationSuccessHandler)
            )
            .rememberMe(rememberMe -> rememberMe
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(86400) // 1 day
            )
            .formLogin(form -> form
                .loginPage("/api/users/login")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/api/users/logout")
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .addFilterBefore(sessionAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow specific origins instead of "*" for better security
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",  // React development server
            "http://localhost:8080",  // Local development server
            "https://yourdomain.com"  // Production domain (replace with your actual domain)
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type", 
            "X-User-ID", 
            "Access-Control-Allow-Origin", 
            "Access-Control-Allow-Headers", 
            "Origin"
        ));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Disposition"));
        // Allow cookies for cross-origin requests if needed
        configuration.setAllowCredentials(true);
        // Cache preflight requests for 1 hour (3600 seconds)
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}
