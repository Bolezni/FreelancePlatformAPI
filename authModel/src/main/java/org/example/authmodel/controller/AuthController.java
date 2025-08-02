package org.example.authmodel.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.authmodel.dto.ApiResponse;
import org.example.authmodel.dto.LoginRequest;
import org.example.authmodel.dto.LoginResponse;
import org.example.authmodel.dto.RegisterRequest;
import org.example.authmodel.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody @Valid LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        LoginResponse loginResponse = authService.login(loginRequest, request, response);
        ApiResponse<LoginResponse> apiResponse = new ApiResponse<>(true, loginResponse, "Successful login");
        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@RequestBody @Valid RegisterRequest registerRequest) {
        authService.register(registerRequest);
        ApiResponse<Void> apiResponse = new ApiResponse<>(true, null, "Successful registration");
        return ResponseEntity.ok(apiResponse);
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        ApiResponse<Void> apiResponse = new ApiResponse<>(true, null, "Successful logout");
        return ResponseEntity.ok(apiResponse);
    }
}
