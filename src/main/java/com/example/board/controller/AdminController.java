package com.example.board.controller;

import com.example.board.model.Post;
import com.example.board.model.User;
import com.example.board.repository.PostRepository;
import com.example.board.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Controller
@RequiredArgsConstructor
public class AdminController {
    private final UserRepository userRepository;
    private final PostRepository postRepository;

    private static final String ADMIN_URL = "/secure-admin-4b7f1a2";

    private static final List<String> ALLOWED_IPS = Arrays.asList(
    		"172.30.1.26",
            "127.0.0.1",    
            "192.168.1.100"
    );

    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    private final Map<String, Integer> loginAttempts = new HashMap<>();

    private boolean isIpAllowed(String clientIp) {
        return ALLOWED_IPS.contains(clientIp);
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @GetMapping(ADMIN_URL)
    public String adminLoginPage(HttpServletRequest request) {
        String clientIp = getClientIp(request);
        if (!isIpAllowed(clientIp)) {
            return "error/403";
        }
        return "admin_login";
    }

    @PostMapping(ADMIN_URL + "/login")
    public String adminLogin(@RequestParam String adminId, @RequestParam String adminPassword,
                             @RequestParam("g-recaptcha-response") String recaptchaResponse,
                             HttpSession session, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        if (!isIpAllowed(clientIp)) {
            return "error/403";
        }

        loginAttempts.putIfAbsent(clientIp, 0);
        if (loginAttempts.get(clientIp) >= 5) {
            return "redirect:" + ADMIN_URL + "?error=locked";
        }

        if (!verifyRecaptcha(recaptchaResponse)) {
            return "redirect:" + ADMIN_URL + "?error=recaptcha_failed";
        }

        if (adminId.equals(System.getenv("ADMIN_ID")) && adminPassword.equals(System.getenv("ADMIN_PASSWORD"))) {
            session.setAttribute("adminId", adminId);
            loginAttempts.remove(clientIp);
            return "redirect:" + ADMIN_URL + "/verify";
        }

        loginAttempts.put(clientIp, loginAttempts.get(clientIp) + 1);
        return "redirect:" + ADMIN_URL + "?error";
    }

    private boolean verifyRecaptcha(String recaptchaResponse) {
        String url = "https://www.google.com/recaptcha/api/siteverify?secret=" + recaptchaSecret + "&response=" + recaptchaResponse;
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(url, null, Map.class);
        Map<String, Object> body = response.getBody();

        return body != null && Boolean.TRUE.equals(body.get("success"));
    }

    @GetMapping(ADMIN_URL + "/verify")
    public String adminVerifyPage(HttpSession session, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        if (!isIpAllowed(clientIp)) {
            return "error/403";
        }

        if (session.getAttribute("adminId") == null) {
            return "redirect:" + ADMIN_URL;
        }
        return "admin_verify";
    }

    @PostMapping(ADMIN_URL + "/verify")
    public String verifySecondPassword(@RequestParam String secondPassword, HttpSession session, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        if (!isIpAllowed(clientIp)) {
            return "error/403";
        }

        if (session.getAttribute("adminId") == null) {
            return "redirect:" + ADMIN_URL;
        }

        if (secondPassword.equals(System.getenv("ADMIN_SECOND_PASSWORD"))) {
            session.setAttribute("isAdmin", true);
            return "redirect:" + ADMIN_URL + "/dashboard";
        }

        session.invalidate();
        return "redirect:" + ADMIN_URL + "?error=invalid_2fa";
    }

    @GetMapping(ADMIN_URL + "/dashboard")
    public String adminDashboard(HttpSession session, Model model, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        if (!isIpAllowed(clientIp)) {
            return "error/403";
        }

        Boolean isAdmin = (Boolean) session.getAttribute("isAdmin");
        if (isAdmin == null || !isAdmin) {
            return "redirect:" + ADMIN_URL;
        }

        String today = LocalDate.now().format(DateTimeFormatter.ISO_DATE);
        model.addAttribute("today", today);

        List<User> users = userRepository.findAll();
        List<Post> posts = postRepository.findAll();
        model.addAttribute("users", users);
        model.addAttribute("posts", posts);

        return "admin_dashboard";
    }

    @GetMapping("/error/403")
    public String accessDenied() {
        return "error/403";
    }
}
