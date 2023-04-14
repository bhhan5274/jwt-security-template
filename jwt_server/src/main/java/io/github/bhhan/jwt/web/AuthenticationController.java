package io.github.bhhan.jwt.web;

import io.github.bhhan.jwt.service.AuthDto;
import io.github.bhhan.jwt.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthDto.AccessTokenResponse> register(
            @RequestBody AuthDto.RegisterRequest request
    ) {
        AuthDto.AuthenticationResponse authenticationResponse = authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .header(HttpHeaders.SET_COOKIE,
                        makeRefreshTokenCookie(authenticationResponse))
                .body(authenticationResponse.toAccessTokenResponse());
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthDto.AccessTokenResponse> authenticate(
            @RequestBody AuthDto.AuthenticationRequest request
    ) {
        AuthDto.AuthenticationResponse authenticationResponse = authService.authenticate(request);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        makeRefreshTokenCookie(authenticationResponse))
                .body(authenticationResponse.toAccessTokenResponse());
    }

    @GetMapping("/refresh")
    public ResponseEntity<AuthDto.AccessTokenResponse> refresh(
            @CookieValue(name = "refresh-token", defaultValue = "") String refreshToken
    ) {
        if(refreshToken.isBlank()) {
            throw new IllegalArgumentException("No Search RefreshToken");
        }

        AuthDto.AuthenticationResponse authenticationResponse = authService.refreshToken(refreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        makeRefreshTokenCookie(authenticationResponse))
                .body(authenticationResponse.toAccessTokenResponse());
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(){
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, ResponseCookie.from("refresh-token", "")
                        .maxAge(0)
                        .path("/")
                        .build()
                        .toString())
                .body("logout success");
    }

    private static String makeRefreshTokenCookie(AuthDto.AuthenticationResponse authenticationResponse) {
        return ResponseCookie.from("refresh-token", authenticationResponse.getRefreshToken())
                .httpOnly(true)
                .sameSite("None")
                .path("/api/v1/auth/refresh")
                .build()
                .toString();
    }
}
