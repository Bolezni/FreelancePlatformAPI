package org.example.authmodel.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.authmodel.dto.LoginRequest;
import org.example.authmodel.dto.LoginResponse;
import org.example.authmodel.dto.RegisterRequest;

public interface AuthService {

    LoginResponse login(LoginRequest loginRequest, HttpServletRequest httpServletRequest, HttpServletResponse response);

    void register(RegisterRequest registerRequest);

    void logout(HttpServletRequest request,HttpServletResponse response);
}
