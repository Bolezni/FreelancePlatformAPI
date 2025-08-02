package org.example.authmodel.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authmodel.dto.LoginRequest;
import org.example.authmodel.dto.RegisterRequest;
import org.example.authmodel.model.UserEntity;
import org.example.authmodel.repository.UserRepository;
import org.example.authmodel.security.CustomUserDetails;
import org.example.authmodel.security.JwtService;
import org.example.authmodel.service.AuthService;
import org.example.authmodel.utils.CookieUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    public void login(LoginRequest loginRequest, HttpServletRequest httpServletRequest, HttpServletResponse response) {
        if (loginRequest == null) {
            throw new IllegalArgumentException("loginRequest cannot be null");
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.username(),
                loginRequest.password()
        ));
        System.out.println("Method Login, username: " + loginRequest.username());

        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(loginRequest.username());

        String jwtToken = jwtService.createJwtToken(userDetails);
        String refreshToken = jwtService.createJwtTokenRefreshToken(userDetails);

        HttpSession session = httpServletRequest.getSession(true);

        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext());

        CsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        CsrfToken csrfToken = csrfTokenRepository.generateToken(httpServletRequest);
        csrfTokenRepository.saveToken(csrfToken, httpServletRequest, response);

        CookieUtils.addCookie(response, jwtService.getTokenName(), jwtToken, jwtService.getTokenExpiration());
        CookieUtils.addCookie(response, jwtService.getRefreshToken(), refreshToken, jwtService.getTokenExpiration());
    }

    @Override
    @Transactional
    public void register(RegisterRequest registerRequest) {

        if (registerRequest == null) {
            throw new IllegalArgumentException("RegisterRequest is null");
        }

        String username = registerRequest.username();
        String email = registerRequest.email();

        System.out.println("Method Register, username: " + username);

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
        log.info("Starting logout process");

        invalidToken(jwtService.getTokenName(), response);
        invalidToken(jwtService.getRefreshToken(), response);

        invalidToken(DEFAULT_CSRF_COOKIE_NAME, response);

        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            log.debug("Invalidating session: {}", sessionId);

            try {
                session.invalidate();
                log.debug("Session invalidated successfully: {}", sessionId);
            } catch (IllegalStateException e) {
                log.debug("Session already invalidated: {}", sessionId);
            }
        }

        SecurityContextHolder.clearContext();

        log.info("Logout completed successfully");
    }

    private void invalidToken(String name, HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(name)
                .value("")
                .maxAge(0)
                .path("/")
                .secure(true)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
