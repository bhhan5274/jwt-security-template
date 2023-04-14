package io.github.bhhan.jwt.service;

import io.github.bhhan.jwt.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    public void addUser(UserDto.UserRequest request) {
        request.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(request.toUser());
    }

    public UserDto.UserResponse userInfo(String email) {
        return new UserDto.UserResponse(userRepository.findByEmail(email).orElseThrow(
                () -> new UsernameNotFoundException("User not found: " + email)
        ));
    }
}
