package io.github.bhhan.jwt.domain.user;

public enum Role {
    USER,
    ADMIN;

    public String roleName(){
        return "ROLE_" + name();
    }
}
