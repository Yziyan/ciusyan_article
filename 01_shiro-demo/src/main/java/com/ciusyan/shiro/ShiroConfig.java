package com.ciusyan.shiro;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {

    @Bean
    public Realm realm() {
        return new TokenRealm(new TokenMatcher());
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(Realm realm) {
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();

        // 设置安全管理器
        factoryBean.setSecurityManager(new DefaultWebSecurityManager(realm));

        // 设置自定义过滤器
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("token", new TokenFilter());
        factoryBean.setFilters(filterMap);

        // 设置URI映射 [需要有序]
        Map<String, String> uriMap = new LinkedHashMap<>();
        // 放行登录的 URI -> 使用自带的匿名过滤器
        uriMap.put("/shiro/login", "anon");
        // ... 若还需要添加其他放行接口，继续添加即可

        // 其余的 URI 需要使用自定义的 过滤器 TokenFilter 过滤
        uriMap.put("/**", "token");

        factoryBean.setFilterChainDefinitionMap(uriMap);

        return factoryBean;
    }

}
