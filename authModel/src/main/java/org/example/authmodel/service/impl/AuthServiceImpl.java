package org.example.authmodel.service.impl;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authmodel.dto.LoginRequest;
import org.example.authmodel.dto.RegisterRequest;
import org.example.authmodel.model.UserEntity;
import org.example.authmodel.repository.UserRepository;
import org.example.authmodel.security.CustomUserDetails;
import org.example.authmodel.security.JwtService;
import org.example.authmodel.service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    public void login(LoginRequest loginRequest, HttpServletResponse response) {
        if (loginRequest == null) {
            throw new IllegalArgumentException("loginRequest cannot be null");
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.username(),
                loginRequest.password()
        ));

        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(loginRequest.username());

        String jwtToken = jwtService.createJwtToken(userDetails);
        String refreshToken = jwtService.createJwtTokenRefreshToken(userDetails);


        ResponseCookie cookieJwtToken = ResponseCookie.from(jwtService.getTokenName())
                .value(jwtToken)
                .maxAge(jwtService.getTokenExpiration())
                .path("/")
                .build();

        ResponseCookie cookieRefreshToken = ResponseCookie.from(jwtService.getRefreshToken())
                .value(refreshToken)
                .maxAge(jwtService.getRefreshTokenExpiration())
                .path("/")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookieJwtToken.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, cookieRefreshToken.toString());
    }

    @Override
    @Transactional
    public void register(RegisterRequest registerRequest) {

        if (registerRequest == null) {
            throw new IllegalArgumentException("RegisterRequest is null");
        }

        String username = registerRequest.username();
        String email = registerRequest.email();

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already exist");
        }

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exist");
        }

        UserEntity userEntity = UserEntity.builder()
                .firstName(registerRequest.firstname())
                .lastName(registerRequest.lastname())
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(registerRequest.password()))
                .build();

        userRepository.save(userEntity);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        boolean isJwtTokenRemove = false;
        boolean isRefreshTokenRemove = false;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(jwtService.getTokenName())) {
                invalidToken(jwtService.getTokenName(), response);
                isJwtTokenRemove = true;
            }
            if (cookie.getName().equals(jwtService.getRefreshToken())) {
                invalidToken(jwtService.getRefreshToken(), response);
                isRefreshTokenRemove = true;
            }
        }

        if (!isJwtTokenRemove || !isRefreshTokenRemove) {
            log.warn("Jwt or Refresh token cookie not found during logout ");
        }

        SecurityContextHolder.clearContext();
    }

    private void invalidToken(String name, HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(name)
                .maxAge(0)
                .path("/")
                .secure(true)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
