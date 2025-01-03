package com.example.board.model;


import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class Post {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String content;

    private String author; // 작성자
    private String password; // 글 비밀번호

    private String department; // 게시판 부서
    private String filePath; // 파일경로 및 이름
}
