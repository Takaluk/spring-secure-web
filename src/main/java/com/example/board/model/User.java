package com.example.board.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String department; // 개발, 인사, 보안
    private String role; // 직급: 부장, 사원
}
