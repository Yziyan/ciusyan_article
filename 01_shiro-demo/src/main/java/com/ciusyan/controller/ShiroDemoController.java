package com.ciusyan.controller;

import com.ciusyan.entity.User;
import com.ciusyan.entity.UserVo;
import com.ciusyan.util.Caches;
import com.ciusyan.util.Dbs;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/shiro")
public class ShiroDemoController {


    @PostMapping("/login")
    public String login(@RequestBody User user) {
        UserVo userVo = Dbs.get(user.getUsername(), user.getPassword());
        if (userVo == null) return "用户名或者密码错误";

        String token = UUID.randomUUID().toString();
        // 通过 token 缓存用户信息
        Caches.putToken(token, userVo);

        return token;
    }


    @GetMapping("/get")
    @RequiresRoles("admin")
    @RequiresPermissions("shiro:read")
    public UserVo get(@RequestParam String username) {
        if (!StringUtils.hasLength(username)) return null;
        return Dbs.getUser(username);
    }


    @GetMapping("/adminOrNormal")
    @RequiresRoles(value = {
            "admin", "normal"
    }, logical = Logical.OR)
    public String adminOrNormal() {
        return "这个接口需要时 [admin] Or [normal] 角色";
    }


    @GetMapping("/not")
    public String not() {
        return "这个接口不需要任何角色和权限";
    }

    @GetMapping("/creat")
    @RequiresPermissions("shiro:create")
    public String creat() {
        return "这个接口需要 [shiro:create] 权限";
    }

    @GetMapping("/deleteAndCreate")
    @RequiresPermissions(value = {
            "shiro:delete","shiro:create"
    }, logical = Logical.AND)
    public String deleteAndCreate() {
        return "这个接口需要 [shiro:delete] And [shiro:create] 权限";
    }

}
