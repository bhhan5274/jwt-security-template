package io.github.bhhan.jwt.service;

import io.github.bhhan.jwt.domain.user.Role;
import io.github.bhhan.jwt.domain.user.User;
import lombok.*;

public class UserDto {
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserRequest {
        private String firstName;
        private String lastName;
        private String email;
        private String password;
        private Role role;

        public User toUser() {
            return User.builder()
                    .firstName(firstName)
                    .lastName(lastName)
                    .email(email)
                    .password(password)
                    .role(role)
                    .build();
        }
    }

    @Data
    @NoArgsConstructor
    public static class UserResponse {
        private String firstName;
        private String lastName;
        private String email;

        public UserResponse(User user) {
            this.firstName = user.getFirstName();
            this.lastName = user.getLastName();
            this.email = user.getEmail();
        }
    }
}
