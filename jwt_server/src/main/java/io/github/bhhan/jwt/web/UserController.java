package io.github.bhhan.jwt.web;

import io.github.bhhan.jwt.service.UserDto;
import io.github.bhhan.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/info")
    public UserDto.UserResponse userInfo(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.userInfo(userDetails.getUsername());
    }
}
