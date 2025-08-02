package org.example.authmodel.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import java.util.HashMap;
import java.util.Map;

public final class CookieUtils {

    private CookieUtils() {}

    public static void addCookie(final HttpServletResponse response, final Map<String, String> cookies) {
        ResponseCookie cookie = ResponseCookie
                .from(cookies.getOrDefault("name", ""))
                .value(cookies.getOrDefault("value", ""))
                .maxAge(Long.parseLong(cookies.getOrDefault("maxAge", "0")))
                .path(cookies.getOrDefault("path", "/"))
                .httpOnly(Boolean.parseBoolean(cookies.getOrDefault("httpOnly", "false")))
                .secure(Boolean.parseBoolean(cookies.getOrDefault("secure", "false")))
                .sameSite(cookies.getOrDefault("sameSite", "Lax"))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public static void addCookie(final HttpServletResponse response, final String name,
                                 final String value,
                                 final Long maxAge) {
        Map<String, String> cookies = new HashMap<>();
        cookies.put("name", name);
        cookies.put("value", value);
        cookies.put("maxAge", String.valueOf(maxAge));
        addCookie(response, cookies);
    }

}
