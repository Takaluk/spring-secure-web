package com.example.board.controller;

import com.example.board.model.Post;
import com.example.board.model.User;
import com.example.board.repository.PostRepository;
import com.example.board.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class AdminController {
    private final UserRepository userRepository;
    private final PostRepository postRepository;

    // Admin login page
    @GetMapping("/admin")
    public String adminLoginPage() {
        return "admin_login";
    }

    // Handle admin login
    @PostMapping("/admin/login")
    public String adminLogin(@RequestParam String adminId, @RequestParam String adminPassword, HttpSession session) {
        if ("admin".equals(adminId) && "admin123".equals(adminPassword)) {
            session.setAttribute("isAdmin", true);
            return "redirect:/admin/dashboard";
        }
        return "redirect:/admin?error";
    }

    // Admin dashboard
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

    // Add a new user
    @PostMapping("/admin/user/add")
    public String addUser(@RequestParam String username, @RequestParam String password,
                          @RequestParam String department, @RequestParam String role) {
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(password);
        newUser.setDepartment(department);
        newUser.setRole(role);
        userRepository.save(newUser);
        return "redirect:/admin/dashboard";
    }

    // Add a new post
    @PostMapping("/admin/post/add")
    public String addPost(@RequestParam String title, @RequestParam String content,
                          @RequestParam String author, @RequestParam String password,
                          @RequestParam String department) {
        Post newPost = new Post();
        newPost.setTitle(title);
        newPost.setContent(content);
        newPost.setAuthor(author);
        newPost.setPassword(password); // 민감 정보 평문 저장
        newPost.setDepartment(department);
        postRepository.save(newPost);
        return "redirect:/admin/dashboard";
    }

    // Delete a user
    @PostMapping("/admin/user/{id}/delete")
    public String deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return "redirect:/admin/dashboard";
    }

    // Delete a post
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

        // 명령어 화이트리스트
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
                model.addAttribute("commandOutput", "Error: Unauthorized command.");
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
            model.addAttribute("commandOutput", "Error: " + e.getMessage());
        }

        model.addAttribute("users", userRepository.findAll());
        model.addAttribute("posts", postRepository.findAll());
        return "admin_dashboard";
    }



}
