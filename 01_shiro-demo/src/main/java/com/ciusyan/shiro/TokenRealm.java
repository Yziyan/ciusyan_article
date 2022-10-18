package com.ciusyan.shiro;

import com.ciusyan.entity.UserVo;
import com.ciusyan.util.Caches;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Set;

/**
 * 自定义 Realm 数据源
 */
public class TokenRealm extends AuthorizingRealm {

    public TokenRealm(CredentialsMatcher credentialsMatcher) {
        super(credentialsMatcher);
    }

    /**
     * 支持的 token 类型
     * @param token：认证时传入的 token
     * @return ：是否支持
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof Token;
    }

    /**
     * 授权器
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String token = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        // 从缓存中取出用户信息
        UserVo userInfo = Caches.getToken(token);
        if (userInfo == null) return info;

        // 添加角色信息
        Set<String> roles = userInfo.getRoles();
        if (!CollectionUtils.isEmpty(roles))
            info.setRoles(roles);

        // 添加权限信息
        Set<String> permissions = userInfo.getPermissions();
        if (!CollectionUtils.isEmpty(permissions))
        info.setStringPermissions(permissions);

        return info;
    }

    /**
     * 认证器
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String tk = ((Token) token).getToken();
        return new SimpleAuthenticationInfo(tk, tk, getName());
    }
}
