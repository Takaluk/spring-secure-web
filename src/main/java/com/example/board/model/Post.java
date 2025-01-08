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

    private String author; 
    private String password; 

    private String department; 
    private String filePath; 
}
