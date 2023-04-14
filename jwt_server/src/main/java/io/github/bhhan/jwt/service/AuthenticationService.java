package io.github.bhhan.jwt.service;


import io.github.bhhan.jwt.domain.user.Role;
import io.github.bhhan.jwt.domain.user.User;
import io.github.bhhan.jwt.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthDto.AuthenticationResponse register(AuthDto.RegisterRequest request) {
        User savedUser = userRepository.save(makeUser(request));
        String jwtToken = jwtService.generateToken(savedUser);
        String refreshToken = jwtService.generateRefreshToken(savedUser);

        return makeAuthenticationResponse(jwtToken, refreshToken);
    }

    public AuthDto.AuthenticationResponse authenticate(AuthDto.AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository
                .findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User Email not found: " + request.getEmail()));

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return makeAuthenticationResponse(jwtToken, refreshToken);
    }

    public AuthDto.AuthenticationResponse refreshToken(
            String refreshToken
    ) {
        String userEmail = Optional.of(jwtService.extractUsername(refreshToken))
                .orElseThrow(() -> new IllegalArgumentException("Wrong RefreshToken: " + refreshToken));

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userEmail));

        if (jwtService.isTokenValid(refreshToken, user)) {
            return AuthDto.AuthenticationResponse.builder()
                    .accessToken(jwtService.generateToken(user))
                    .refreshToken(jwtService.generateRefreshToken(user))
                    .build();
        }

        throw new IllegalArgumentException("RefreshToken is expired: " + refreshToken);
    }

    private User makeUser(AuthDto.RegisterRequest request) {
        return User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
    }

    private static AuthDto.AuthenticationResponse makeAuthenticationResponse(String jwtToken, String refreshToken) {
        return AuthDto.AuthenticationResponse
                .builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
}
