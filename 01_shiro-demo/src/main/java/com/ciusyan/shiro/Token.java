package com.ciusyan.shiro;

import lombok.Data;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * 自定义 Token 校验规则
 */
@Data
public class Token implements AuthenticationToken {
    private final String token;

    public Token(String token) { this.token = token; }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
