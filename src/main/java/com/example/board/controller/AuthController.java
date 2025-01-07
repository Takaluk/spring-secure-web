package com.example.board.controller;

import com.example.board.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    private final Map<String, Integer> loginAttempts = new HashMap<>();

    private boolean verifyRecaptcha(String recaptchaResponse) {
        String url = "https://www.google.com/recaptcha/api/siteverify?secret=" + recaptchaSecret + "&response=" + recaptchaResponse;
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(url, null, Map.class);
        Map<String, Object> body = response.getBody();

        if (body == null || !Boolean.TRUE.equals(body.get("success"))) {
            return false;
        }
        return true;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // login.html 반환
    }

    @PostMapping("/perform-login") 
    public String login(@RequestParam String username, @RequestParam String password, HttpSession session, @RequestParam("g-recaptcha-response") String recaptchaResponse,
    HttpServletRequest request) {
        String clientIp = getClientIp(request);
        loginAttempts.putIfAbsent(clientIp, 0);


        if (loginAttempts.get(clientIp) >= 5) {
            return "redirect:/login?error=locked";
        }

        if (!verifyRecaptcha(recaptchaResponse)) {
            return "redirect:/login?error=recaptcha_failed";
        }
        loginAttempts.put(clientIp, loginAttempts.get(clientIp) + 1);
        
        return authService.login(username, password)
                .map(user -> {
                    session.setAttribute("user", user);
                    return "redirect:/";
                })
                .orElse("redirect:/login?error");
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
    
    @GetMapping("/find-password")
    public String findPasswordPage() {
        return "find-password"; // find-password.html 반환
    }

    @PostMapping("/find-password")
    public String findPassword(
            @RequestParam String username,
            @RequestParam String department,
            @RequestParam String role,
            Model model) {
        return authService.findPassword(username, department, role)
                .map(password -> {
                    model.addAttribute("password", password);
                    return "password-result"; // password-result.html 반환
                })
                .orElse("redirect:/find-password?error");
    }

}

