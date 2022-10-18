package com.ciusyan.util;

import com.ciusyan.entity.UserVo;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 模拟缓存
 */
public class Caches {

    /**
     * 将用户信息，用 Token 缓存在 Map 中
     */
    private static final Map<String, UserVo> CACHE_USER;

    static {
        CACHE_USER = new HashMap<>();
    }

    /**
     * 放入缓存
     * @param key：Token
     * @param value：用户信息
     */
    public static void putToken(String key, UserVo value) {
        if (!StringUtils.hasLength(key) || value == null) return;
        CACHE_USER.put(key, value);
    }

    /**
     * 取出缓存信息
     * @param key：Token
     * @return ：用户信息
     */
    public static UserVo getToken(String key) {
        if (!StringUtils.hasLength(key)) return null;
        return CACHE_USER.get(key);
    }
}
