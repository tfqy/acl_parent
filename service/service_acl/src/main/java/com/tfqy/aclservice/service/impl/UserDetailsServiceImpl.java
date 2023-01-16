package com.tfqy.aclservice.service.impl;

import com.tfqy.aclservice.entity.User;
import com.tfqy.aclservice.service.PermissionService;
import com.tfqy.aclservice.service.UserService;
import com.tfqy.entity.SecurityUser;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 2023/1/16 11:49
 *
 * @author tfqy
 */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private UserService userService;
    @Resource
    private PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名获取用户信息
        User user = userService.selectByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }
        com.tfqy.entity.User curUser = new com.tfqy.entity.User();
        BeanUtils.copyProperties(user, curUser);
        //根据用户id获取用户权限
        SecurityUser securityUser = new SecurityUser();
        List<String> pemissionValueList = permissionService.selectPermissionValueByUserId(user.getId());
        securityUser.setPermissionValueList(pemissionValueList);
        securityUser.setCurrentUserInfo(curUser);
        return securityUser;
    }
}
