package com.ciusyan.shiro;

import com.ciusyan.util.Caches;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * 自定义过滤器
 */
public class TokenFilter extends AccessControlFilter {

    public static final String TOKEN_HEADER = "Token";

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // 直接返回 false ，在onAccessDenied方法中统一处理
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader(TOKEN_HEADER);

        // 验证Token是否存在
        if (!StringUtils.hasLength(token)) {
            throw new IllegalArgumentException("没有Token，请登录");
        }

        // 验证Token是否过期
        if (Caches.getToken(token) == null) {
            throw new IllegalArgumentException("Token已过期，请重新登录");
        }

        // 去认证
        SecurityUtils.getSubject().login(new Token(token));

        return true;
    }
}
