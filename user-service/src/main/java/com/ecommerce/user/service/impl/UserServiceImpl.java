package com.ecommerce.user.service.impl;

import com.ecommerce.user.Repository.RoleRepository;
import com.ecommerce.user.Repository.UserRepository;
import com.ecommerce.user.dtos.request.SignUpRequestDto;
import com.ecommerce.user.dtos.response.UserResponseDto;
import com.ecommerce.user.entity.Role;
import com.ecommerce.user.entity.User;
import com.ecommerce.user.enums.RoleName;
import com.ecommerce.user.exceptions.DataNotFoundException;
import com.ecommerce.user.exceptions.EntityExistsException;
import com.ecommerce.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * =====================================================================================
 * FILE: UserServiceImpl.java
 * MODULE: user-service
 * PURPOSE: Implements UserService business logic, password encryption, and JPA persistence.
 * <p>
 * DESIGN PATTERN: Service Layer Implementation Pattern.
 * <p>
 * READING ORDER:
 * - Read PREVIOUS: UserService.java, UserRepository.java
 * - Read THIS FILE: Understand user persistence and role assignment.
 * - Read NEXT: AuthServiceImpl.java, UserController.java
 * <p>
 * TRICKY INTERVIEW QUESTIONS & ARCHITECTURAL WISDOM:
 * Q1: What happens if an exception is thrown inside a method annotated with `@Transactional`?
 * A1: By default, Spring's TransactionInterceptor marks the transaction for ROLLBACK only
 * for unchecked exceptions (subclasses of `RuntimeException` and `Error`). Checked exceptions
 * (`Exception`) commit by default unless explicitly configured via `@Transactional(rollbackFor = Exception.class)`.
 * <p>
 * =====================================================================================
 * SERVICE & TRANSACTION ANNOTATIONS MASTERCLASS:
 * =====================================================================================
 * 1. @Service vs @Component:
 * - @Service is a specialized @Component. While functionally identical in bean creation,
 *
 * @Service declares that this bean contains domain business logic. It also enables
 * architectural pointcuts in Spring AOP (e.g. logging all calls within com..service.*).
 * <p>
 * 2. @Transactional (Write) vs @Transactional(readOnly = true):
 * - @Transactional (Default): Starts a database transaction. Hibernate takes memory snapshots
 * of all queried entities for dirty-checking. When the method completes, any modified fields
 * are automatically written via SQL UPDATE statements, and the transaction commits.
 * - @Transactional(readOnly = true): Tells Hibernate this is a pure read operation. Hibernate
 * can skip dirty-checking work, saving CPU and heap RAM. It does not automatically route queries
 * to secondary replicas; that needs explicit datasource-routing configuration.
 * <p>
 * 3. Self-Invocation Pitfall with @Transactional:
 * - If Method A (non-transactional) calls Method B (@Transactional) in the same class:
 * this.methodB();
 * The transaction will NOT start! Spring @Transactional relies on CGLIB dynamic proxies.
 * Internal `this` calls bypass the proxy interceptor entirely!
 * =====================================================================================
 */

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserResponseDto createuser(SignUpRequestDto requestDto) {

        if (userRepository.existsByEmailIgnoreCaseAndIsActiveTrue(requestDto.getEmail())) {
            throw new EntityExistsException("User already exists with email: " + requestDto.getEmail());
        }

        Role userRole = roleRepository.findByNameIgnoreCaseAndIsActiveTrue(RoleName.ROLE_USER.name())
                .orElseThrow(() -> new DataNotFoundException("Default role ROLE_USER not found in database"));

        User user = new User();

        user.setName(requestDto.getName());
        user.setEmail(requestDto.getEmail());
        user.setMobileNo(requestDto.getMobileNo());
        user.setPassword(passwordEncoder.encode(requestDto.getPassword()));
        user.setRoles(Set.of(userRole));

        User savedUser = userRepository.save(user);

        return mapToUserResponseDto(savedUser);
    }


    @Override
    public UserResponseDto getUserById(Long id) {

        User user = userRepository.findByIdAndIsActiveTrue(id)
                .orElseThrow(() -> new DataNotFoundException("User not Found :" + id));
        return mapToUserResponseDto(user);
    }

    @Override
    public List<UserResponseDto> getAll() {

        return userRepository.findAllAndIsActiveTrue()
                .stream().map(this::mapToUserResponseDto)
                .toList();
    }

    private UserResponseDto mapToUserResponseDto(User user) {
        return UserResponseDto.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .mobileNo(user.getMobileNo())
                .profileUrl(user.getProfileUrl())
                .roles(user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .build();
    }
}
