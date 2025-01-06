package com.example.board.controller;

import com.example.board.model.Post;
import com.example.board.model.User;
import com.example.board.service.BoardService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class BoardController {
    private final BoardService boardService;

    
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
                         @RequestParam("file") MultipartFile file) throws UnsupportedEncodingException {
    // Set department for the post
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
            Path targetPath = uploadPath.resolve(originalFileName);
            file.transferTo(targetPath);

            // 파일 경로를 Post 객체에 저장
            post.setFilePath(targetPath.toString());  // DB에 저장할 파일 경로 설정
        } catch (IOException e) {
            e.printStackTrace();
            // 파일 처리 중 오류가 발생하면 적절한 예외 처리를 해야 함
            return "error";  // 에러 페이지로 리턴 (예: 오류 메시지를 보여주는 페이지)
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
