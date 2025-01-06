package com.example.board.controller;

import com.example.board.model.Post;
import com.example.board.model.User;
import com.example.board.repository.PostRepository;
import com.example.board.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

@Controller
@RequiredArgsConstructor
public class AdminController {
    private final UserRepository userRepository;
    private final PostRepository postRepository;

    @GetMapping("/admin")
    public String adminLoginPage() {
        return "admin_login";
    }

    private final Map<String, Integer> loginAttempts = new HashMap<>();
    
    @Value("${recaptcha.secret}")
    private String recaptchaSecret;
    
    @PostMapping("/admin/login")
    public String adminLogin(@RequestParam String adminId, @RequestParam String adminPassword,
            @RequestParam("g-recaptcha-response") String recaptchaResponse,
            HttpSession session, HttpServletRequest request) {        
    	String clientIp = getClientIp(request);
        loginAttempts.putIfAbsent(clientIp, 0);

        if (loginAttempts.get(clientIp) >= 5) {
            return "redirect:/admin?error=locked";
        }
        
        if (!verifyRecaptcha(recaptchaResponse)) {
            return "redirect:/admin?error=recaptcha_failed";
        }

        if (adminId.equals(System.getenv("ADMIN_ID")) && adminPassword.equals(System.getenv("ADMIN_PASSWORD"))) {
            session.setAttribute("adminId", adminId); // 2차 인증을 위해 adminId만 저장
            loginAttempts.remove(clientIp);
            return "redirect:/admin/verify";
        }

        loginAttempts.put(clientIp, loginAttempts.get(clientIp) + 1);
        return "redirect:/admin?error";
    }

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
    
    @GetMapping("/admin/verify")
    public String adminVerifyPage(HttpSession session) {
        if (session.getAttribute("adminId") == null) {
            return "redirect:/admin";
        }
        return "admin_verify";
    }

    @PostMapping("/admin/verify")
    public String verifySecondPassword(@RequestParam String secondPassword, HttpSession session) {
        if (session.getAttribute("adminId") == null) {
            return "redirect:/admin";
        }

        if (secondPassword.equals(System.getenv("ADMIN_SECOND_PASSWORD"))) {
            session.setAttribute("isAdmin", true);
            return "redirect:/admin/dashboard";
        }

        session.invalidate(); // 인증 실패 시 세션 초기화
        return "redirect:/admin?error=invalid_2fa";
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



    @GetMapping("/admin/dashboard")
    public String adminDashboard(HttpSession session, Model model) {
        Boolean isAdmin = (Boolean) session.getAttribute("isAdmin");
        if (isAdmin == null || !isAdmin) {
            return "redirect:/admin";
        }
        String today = LocalDate.now().format(DateTimeFormatter.ISO_DATE);
        
        model.addAttribute("today", today);

        List<User> users = userRepository.findAll();
        List<Post> posts = postRepository.findAll();
        model.addAttribute("users", users);
        model.addAttribute("posts", posts);
        return "admin_dashboard";
    }

    @PostMapping("/admin/user/add")
    public String addUser(@RequestParam String username, @RequestParam String password,
                          @RequestParam String department, @RequestParam String role) {
        if (!isValidPassword(password)) {
            return "redirect:/admin/dashboard?error=weak_password";
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(password);
        newUser.setDepartment(department);
        newUser.setRole(role);
        userRepository.save(newUser);
        return "redirect:/admin/dashboard";
    }

    private boolean isValidPassword(String password) {
        if (password.length() < 8) return false;

        int categories = 0;
        if (password.matches(".*[A-Z].*")) categories++;
        if (password.matches(".*[a-z].*")) categories++;
        if (password.matches(".*\\d.*")) categories++;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) categories++;

        return (categories >= 2 && password.length() >= 10) || categories >= 3;
    }


    @PostMapping("/admin/post/add")
    public String addPost(@RequestParam String title, @RequestParam String content,
                          @RequestParam String author, @RequestParam String password,
                          @RequestParam String department) {
        Post newPost = new Post();
        newPost.setTitle(title);
        newPost.setContent(content);
        newPost.setAuthor(author);
        newPost.setPassword(password);
        newPost.setDepartment(department);
        postRepository.save(newPost);
        return "redirect:/admin/dashboard";
    }

    @PostMapping("/admin/user/{id}/delete")
    public String deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return "redirect:/admin/dashboard";
    }

    @PostMapping("/admin/post/{id}/delete")
    public String deletePost(@PathVariable Long id) {
        postRepository.deleteById(id);
        return "redirect:/admin/dashboard";
    }
    
    @PostMapping("/admin/system/command")
    public String executeSystemCommand(@RequestParam String logType, HttpSession session, Model model) {
        Boolean isAdmin = (Boolean) session.getAttribute("isAdmin");
        if (isAdmin == null || !isAdmin) {
            return "redirect:/admin";
        }

        String command;
        switch (logType) {
            case "catalina_log":
                command = "cat /opt/tomcat/tomcat-10/logs/catalina.out";
                break;
            case "access_log":
                String today = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                command = "cat /opt/tomcat/tomcat-10/logs/localhost_access_log." + today + ".txt";
                break;
            default:
                model.addAttribute("commandOutput", "Error: Unauthorized request.");
                return "admin_dashboard";
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command.split(" "));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            model.addAttribute("commandOutput", output.toString());
        } catch (Exception e) {
            model.addAttribute("commandOutput", "Error: Unable to output logs.");
        }

        List<User> users = userRepository.findAll();
        for (User user : users) {
            user.setPassword(null); 
        }
        model.addAttribute("users", users);
        List<Post> posts = postRepository.findAll();
        for (Post post : posts) {
            post.setPassword(null);
        }
        model.addAttribute("posts", posts);

        return "admin_dashboard";
    }
} 
