package org.javaboy.vhr.service;

import org.javaboy.vhr.mapper.MenuMapper;
import org.javaboy.vhr.model.Hr;
import org.javaboy.vhr.model.Menu;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MenuService {
    @Autowired
    MenuMapper menuMapper;
    public List<Menu> getMenuById(){
        return menuMapper.getMenuById(
                ((Hr)SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getId());
    }
//    @Cacheable
    public List<Menu> getAllMenuWithRole(){
        return menuMapper.getAllMenuWithRole();
    }
}
