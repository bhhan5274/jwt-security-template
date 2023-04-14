package io.github.bhhan.jwt;

import io.github.bhhan.jwt.domain.user.Role;
import io.github.bhhan.jwt.service.UserDto;
import io.github.bhhan.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

@Slf4j
@RequiredArgsConstructor
@SpringBootApplication
@Import({
        ApplicationConfig.class,
        SecurityConfig.class,
})
public class App {
    private final UserService userService;

    @Value("${application.security.admin.firstname:John}")
    private String firstname;

    @Value("${application.security.admin.lastname:Doe}")
    private String lastname;

    @Value("${application.security.admin.password:admin}")
    private String password;

    @Value("${application.security.admin.role:ADMIN}")
    private Role role;

    @Value("${application.security.admin.email:admin@email.com}")
    private String email;


    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @Bean
    public ApplicationRunner applicationRunner(){
        return args -> {
            try{
                userService.addUser(UserDto.UserRequest.builder()
                        .firstName(firstname)
                        .lastName(lastname)
                        .role(role)
                        .password(password)
                        .email(email)
                        .build());
            }catch(Exception e){
                log.info("Admin User exist");
            }
        };
    }
}
