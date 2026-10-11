package com.ecommerce.user.Repository;

import com.ecommerce.user.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {

    Optional<RefreshToken> findByTokenJtiAndIsRevokedFalse(String tokenJti);

    @Modifying(clearAutomatically = true)
    @Query("UPDATE RefreshToken r SET r.isRevoked = true WHERE r.userEmail = :userEmail")
    void revokeAllByUserEmail(@Param("userEmail") String userEmail);
}
