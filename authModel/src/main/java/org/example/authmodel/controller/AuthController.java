package org.example.authmodel.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.authmodel.dto.ApiResponse;
import org.example.authmodel.dto.LoginRequest;
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
    public ResponseEntity<ApiResponse<Void>> login(@RequestBody @Valid LoginRequest loginRequest, HttpServletResponse response) {
        ApiResponse<Void> apiResponse;
        try{
            authService.login(loginRequest,response);
            apiResponse = new ApiResponse<>(true, null, "Successful authentication");
            return ResponseEntity.ok(apiResponse);
        }catch(Exception e){
            apiResponse = new ApiResponse<>(false,null,e.getMessage());
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@RequestBody @Valid RegisterRequest registerRequest) {
        ApiResponse<Void> apiResponse;
        try{
            authService.register(registerRequest);
            apiResponse = new ApiResponse<>(true, null, "Successful registration");
            return ResponseEntity.ok(apiResponse);
        }catch(Exception e){
            apiResponse = new ApiResponse<>(false,null,e.getMessage());
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, HttpServletResponse response) {
        ApiResponse<Void> apiResponse;
        try{
            authService.logout(request,response);
            apiResponse = new ApiResponse<>(true, null, "Successful logout");
            return ResponseEntity.ok(apiResponse);
        }catch(Exception e){
            apiResponse = new ApiResponse<>(false,null,e.getMessage());
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }
}
