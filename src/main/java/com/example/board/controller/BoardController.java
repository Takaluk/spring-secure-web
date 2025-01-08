package com.example.board.controller;

import com.example.board.model.Post;
import com.example.board.model.User;
import com.example.board.service.BoardService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class BoardController {
    private final BoardService boardService;

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

    private boolean isAllowedExtension(String extension) {
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "gif", "txt", "mp4", "avi", "mkv");
        if (extension.equals("java") || extension.equals("php") || extension.equals("sh")) {
            return false;
        }
        return allowedExtensions.contains(extension);
    }

    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user == null) return "redirect:/login";

        model.addAttribute("user", user);
        return "home";
    }

    @GetMapping("/board/{department}")
    public String board(@PathVariable String department, HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user == null || (!user.getDepartment().equals(department) && !user.getRole().equals("부장"))) {
        	return "redirect:/login";
        }

        List<Post> posts = boardService.getPostsByDepartment(department);
        model.addAttribute("posts", posts);
        model.addAttribute("department", department);
        return "board";
    }

    @GetMapping("/board/{department}/post/new")
    public String newPostPage(@PathVariable String department, Model model) {
        model.addAttribute("department", department);
        return "post_form";
    }

    @PostMapping("/board/{department}/post")
public String createPost(@PathVariable String department, 
                         Post post, 
                         HttpSession session, 
                         @RequestParam("file") MultipartFile file,
                         @RequestParam("g-recaptcha-response") String recaptchaResponse,
                         HttpServletRequest request) throws UnsupportedEncodingException {
    String clientIp = getClientIp(request);
    loginAttempts.putIfAbsent(clientIp, 0);

    if (loginAttempts.get(clientIp) >= 5) {
        return "redirect:/board/{department}/post/new?error=locked";
    }

    if (!verifyRecaptcha(recaptchaResponse)) {
        return "redirect:/board/{department}/post/new?error=recaptcha_failed";
    }

    post.setDepartment(department);
    
    User user = (User) session.getAttribute("user");
    if (user != null) {
        post.setAuthor(user.getUsername());
    }

    if (!file.isEmpty()) {
        try {
            Path uploadPath = Paths.get("uploads");  
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath); 
            }

            String originalFileName = file.getOriginalFilename();
            if (originalFileName == null) {
                throw new IllegalArgumentException("파일 이름이 없습니다.");
            }
            String extension = originalFileName.substring(originalFileName.lastIndexOf('.') + 1).toLowerCase();
            if (!isAllowedExtension(extension)) {
                throw new IllegalArgumentException("허용되지 않는 파일 형식입니다.");
            }
            Path targetPath = uploadPath.resolve(originalFileName).normalize();
            if (!targetPath.startsWith(uploadPath)) {
                throw new SecurityException("잘못된 파일 경로입니다.");            
            }

            file.transferTo(targetPath);

            post.setFilePath(targetPath.toString()); 
        } catch (IOException e) {
            e.printStackTrace();
            return "redirect:/board/{department}/post/new?error=Directory_Error";
        } catch (IllegalArgumentException | SecurityException e) {
            e.printStackTrace();
            return "redirect:/board/{department}/post/new?error=User_Error";
        }
    }

    boardService.savePost(post);

    String encodedDepartment = URLEncoder.encode(department, "UTF-8");
    return "redirect:/board/" + encodedDepartment;
}

    @PostMapping("/board/{department}/post/{id}/delete")
    public String deletePost(@PathVariable String department, @PathVariable Long id, @RequestParam String password) throws UnsupportedEncodingException {
        boardService.getPostById(id).ifPresent(post -> {
            if (post.getPassword().equals(password)) {
                boardService.deletePost(id);
            }
        });

        String encodedDepartment = URLEncoder.encode(department, "UTF-8");
        return "redirect:/board/" + encodedDepartment;
    }

    @GetMapping("/board/{department}/post/{id}/edit")
    public String showEditForm(@PathVariable String department, @PathVariable Long id, Model model) {
        boardService.getPostById(id).ifPresentOrElse(
            post -> {
                model.addAttribute("post", post);
                model.addAttribute("department", department);
            },
            () -> {
                model.addAttribute("department", department);
            }
        );
        return "post_edit";
    }

    
}
