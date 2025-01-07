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
        // 허용할 확장자 목록
        List<String> allowedExtensions = Arrays.asList("jpg", "jpeg", "png", "gif", "txt", "mp4", "avi", "mkv");
        if (extension.equals("java") || extension.equals("php") || extension.equals("sh")) { // 특히 명시적 제외
            return false;
        }
        return allowedExtensions.contains(extension);
    }
    
    // Home page
    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        if (user == null) return "redirect:/login";

        model.addAttribute("user", user);
        return "home";
    }

    // Board page for a specific department
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

    // Page to create a new post
    @GetMapping("/board/{department}/post/new")
    public String newPostPage(@PathVariable String department, Model model) {
        model.addAttribute("department", department);
        return "post_form";
    }

    // Handle form submission to create a new post
    @PostMapping("/board/{department}/post")
public String createPost(@PathVariable String department, 
                         Post post, 
                         HttpSession session, 
                         @RequestParam("file") MultipartFile file,
                         @RequestParam("g-recaptcha-response") String recaptchaResponse,
                         HttpServletRequest request) throws UnsupportedEncodingException {
    // Set department for the post
    String clientIp = getClientIp(request);
    loginAttempts.putIfAbsent(clientIp, 0);

    if (loginAttempts.get(clientIp) >= 5) {
        return "redirect:/board/{department}/post/new?error=locked";
    }

    if (!verifyRecaptcha(recaptchaResponse)) {
        return "redirect:/board/{department}/post/new?error=recaptcha_failed";
    }

    post.setDepartment(department);
    
    // Optionally, associate the post with the logged-in user
    User user = (User) session.getAttribute("user");
    if (user != null) {
        post.setAuthor(user.getUsername()); // Assuming Post has an author field
    }
    System.out.println("Current working directory: " + System.getProperty("user.dir"));

    // 파일이 첨부된 경우 처리
    if (!file.isEmpty()) {
        try {
            
            // 파일을 저장할 경로 지정 (서버 내의 특정 디렉토리)
            Path uploadPath = Paths.get("uploads");  // "uploads" 디렉토리로 파일 저장
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);  // 디렉토리가 없으면 생성
            }

            String originalFileName = file.getOriginalFilename();
            if (originalFileName == null) {
                throw new IllegalArgumentException("파일 이름이 없습니다.");
            }
            // 파일 확장자 검증
            String extension = originalFileName.substring(originalFileName.lastIndexOf('.') + 1).toLowerCase();
            if (!isAllowedExtension(extension)) {
                throw new IllegalArgumentException("허용되지 않는 파일 형식입니다.");
            }

            // 파일 경로 제한: "uploads" 디렉토리 외부로 저장 방지
            Path targetPath = uploadPath.resolve(originalFileName).normalize();
            if (!targetPath.startsWith(uploadPath)) {
                throw new SecurityException("잘못된 파일 경로입니다.");            
            }

            file.transferTo(targetPath);

            // 파일 경로를 Post 객체에 저장
            post.setFilePath(targetPath.toString());  // DB에 저장할 파일 경로 설정
        } catch (IOException e) {
            e.printStackTrace();
            // 파일 처리 중 오류가 발생하면 적절한 예외 처리를 해야 함
            return "redirect:/board/{department}/post/new?error=Directory_Error";
        } catch (IllegalArgumentException | SecurityException e) {
            e.printStackTrace();
            // 사용자 오류 처리
            return "redirect:/board/{department}/post/new?error=User_Error";
        }
    }

    // DB에 Post 객체 저장 (예: postRepository.save(post) 등)
    boardService.savePost(post);

    // Redirect back to the department's board, ensuring the department name is URL-encoded
    String encodedDepartment = URLEncoder.encode(department, "UTF-8");
    return "redirect:/board/" + encodedDepartment;
}

    // Handle deleting a post
    @PostMapping("/board/{department}/post/{id}/delete")
    public String deletePost(@PathVariable String department, @PathVariable Long id, @RequestParam String password) throws UnsupportedEncodingException {
        boardService.getPostById(id).ifPresent(post -> {
            if (post.getPassword().equals(password)) {
                boardService.deletePost(id);
            }
        });

        // URL-encode the department name in case it contains special characters
        String encodedDepartment = URLEncoder.encode(department, "UTF-8");
        return "redirect:/board/" + encodedDepartment;
    }

    @GetMapping("/board/{department}/post/{id}/edit")
    public String showEditForm(@PathVariable String department, @PathVariable Long id, Model model) {
        // 게시글 가져오기
        boardService.getPostById(id).ifPresentOrElse(
            post -> {
                // 게시글이 존재하면 모델에 추가하고 수정 페이지로 이동
                model.addAttribute("post", post);
                model.addAttribute("department", department);
            },
            () -> {
                // 게시글이 존재하지 않으면 게시판 페이지로 리디렉션
                model.addAttribute("department", department);
            }
        );
        // 결과적으로 수정 페이지로 이동하거나 게시판으로 리디렉션
        return "post_edit";  // 수정 페이지로 이동, 게시글이 없으면 자동으로 리디렉션됨
    }

    
}
