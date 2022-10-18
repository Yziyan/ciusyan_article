package com.ciusyan.util;

import com.ciusyan.entity.User;
import com.ciusyan.entity.UserVo;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 模拟数据库
 */
public class Dbs {

    /**
     * 查询用户，并且需要验证密码
     * @param username：用户名
     * @param password：密码
     * @return ：用户信息
     */
    public static UserVo get(String username, String password) {
        Map<String, UserVo> userMap = userMap();
        UserVo userVo = userMap.get(username);

        // 密码和用户名都正确
        if (userVo != null && userVo.getUser().getPassword().equals(password)) {
            return userVo;
        } else {
            return null;
        }
    }

    /**
     * 根据用户名获取用户信息
     * @param username：用户名
     * @return ：用户信息
     */
    public static UserVo getUser(String username) {
        if (!StringUtils.hasLength(username)) return null;
        Map<String, UserVo> userMap = userMap();
        return userMap.get(username);
    }

    /**
     * 默认有三个用户
     * @return :用户映射
     */
    private static Map<String, UserVo> userMap() {

        UserVo userVo1 = new UserVo(
                new User("zhiyan", "111"),
                Set.of("admin", "teacher"),
                Set.of("shiro:creat", "shiro:read", "shiro:update", "shiro:delete"));

        UserVo userVo2 = new UserVo(
                new User("ciusyan", "222"),
                Set.of("teacher"),
                Set.of("shiro:read", "shiro:update"));

        UserVo userVo3 = new UserVo(
                new User("ZY", "333"),
                Set.of("normal"),
                Set.of("shiro:read"));

        return Map.of("zhiyan", userVo1, "ciusyan", userVo2, "ZY", userVo3);
    }

}
