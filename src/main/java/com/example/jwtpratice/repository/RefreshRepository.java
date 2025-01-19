package com.example.jwtpratice.repository;

import com.example.jwtpratice.entity.Refresh;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshRepository extends JpaRepository<Refresh, Long> {
    boolean existsByRefresh(String refresh);

    @Transactional
    void deleteByEmail(String email);
}
