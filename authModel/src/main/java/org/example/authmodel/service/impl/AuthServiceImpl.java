package org.example.authmodel.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.authmodel.dto.LoginRequest;
import org.example.authmodel.dto.LoginResponse;
import org.example.authmodel.dto.RegisterRequest;
import org.example.authmodel.model.Roles;
import org.example.authmodel.model.UserEntity;
import org.example.authmodel.repository.UserRepository;
import org.example.authmodel.security.CustomUserDetails;
import org.example.authmodel.service.AuthService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SessionRegistry sessionRegistry;

    @Override
    public LoginResponse login(LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        if (loginRequest == null) {
            throw new IllegalArgumentException("loginRequest cannot be null");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.username(),
                        loginRequest.password()));

        log.info("Authenticated user: {}", authentication.getName());


        SecurityContextHolder.getContext().setAuthentication(authentication);

        HttpSession session = request.getSession();

        log.info("New session created: {}", session.getId());

        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext());

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        log.info("User logged in: {}", userDetails.getUser());

        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        return new LoginResponse(
                userDetails.getUser().getUUID(),
                userDetails.getUser().getUsername(),
                userDetails.getUser().getEmail(),
                session.getId(),
                csrfToken.getToken() != null ? csrfToken.getToken() : null
        );
    }

    @Override
    @Transactional
    public void register(RegisterRequest registerRequest) {

        if (registerRequest == null) {
            throw new IllegalArgumentException("RegisterRequest is null");
        }

        String username = registerRequest.username();
        String email = registerRequest.email();

        if (userRepository.existsByUsernameOrEmail(username, email)) {
            throw new IllegalArgumentException("Username or email already exists");
        }

        Set<Roles> roles = registerRequest.roles()
                .stream()
                .map(String::toUpperCase)
                .map(Roles::valueOf)
                .collect(Collectors.toSet());

        if (roles.isEmpty()) {
            roles.add(Roles.CLIENT);
        }

        UserEntity userEntity = UserEntity.builder()
                .firstName(registerRequest.firstname())
                .lastName(registerRequest.lastname())
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(registerRequest.password()))
                .roles(roles)
                .build();

        userRepository.save(userEntity);
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession httpSession = request.getSession();
        if (httpSession != null) {
            String sessionId = httpSession.getId();

            log.debug("Logout sessionId: {}", sessionId);

            SessionInformation sessionInformation = sessionRegistry.getSessionInformation(sessionId);
            if (sessionInformation != null) {
                sessionRegistry.removeSessionInformation(sessionId);
            }

            httpSession.invalidate();
        }

        SecurityContextHolder.clearContext();
    }
}
