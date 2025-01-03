package com.example.board.controller;

import com.example.board.service.AuthService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // login.html 반환
    }

    @PostMapping("/perform-login") // URL 변경
    public String login(@RequestParam String username, @RequestParam String password, HttpSession session) {
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

