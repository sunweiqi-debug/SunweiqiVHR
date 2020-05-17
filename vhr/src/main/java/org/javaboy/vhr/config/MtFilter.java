package org.javaboy.vhr.config;

import org.javaboy.vhr.model.Menu;
import org.javaboy.vhr.model.Role;
import org.javaboy.vhr.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

import static java.awt.SystemColor.menu;

@Component
//这个类用来
public class MtFilter implements FilterInvocationSecurityMetadataSource {
    @Autowired
    MenuService menuService;
    //引入路径path比对类
    AntPathMatcher antPathMatcher=new AntPathMatcher();
    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        String requestUrl=((FilterInvocation)o).getRequestUrl();
        List<Menu> menuList=menuService.getAllMenuWithRole();
        for(Menu menu:menuList){
            if(antPathMatcher.match(menu.getUrl(),requestUrl)){
            List<Role> roles=menu.getRoles();
            String[] str=new String[roles.size()];
            for(int i=0;i<roles.size();i++){
                str[i]=roles.get(i).getName();
            }
            return SecurityConfig.createList(str);
            }
        }
        //没有匹配url的话，分配登陆角色
        return SecurityConfig.createList("ROLE_LOGIN");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
