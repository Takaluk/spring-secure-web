package com.example.board.service;

import com.example.board.model.Post;
import com.example.board.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class BoardService {
    private final PostRepository postRepository;

    public List<Post> getPostsByDepartment(String department) {
        return postRepository.findByDepartment(department);
    }

    public Optional<Post> getPostById(Long id) {
        return postRepository.findById(id);
    }

    public void savePost(Post post) {
        postRepository.save(post);
    }

    public void deletePost(Long id) {
        postRepository.deleteById(id);
    }
}
