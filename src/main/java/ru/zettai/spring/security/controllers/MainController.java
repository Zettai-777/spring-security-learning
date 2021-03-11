package ru.zettai.spring.security.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.zettai.spring.security.entities.User;
import ru.zettai.spring.security.services.UserService;

import java.security.Principal;
import java.util.Collection;

@RestController
public class MainController {

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public String homePage(Principal principal){
        // Проверка имеющихся ауторити у пользователя на главной странице
        if(principal != null){
            Collection<? extends GrantedAuthority> authorities = ((Authentication) principal).getAuthorities();
            System.out.println("User: " + principal.getName() + " have next roles:\n" + authorities);
        }
        return "home";
    }

    @GetMapping("/authenticated")
    public String pageForAuthenticatedUsers(Principal principal){
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication(); //получаем информацию о principal из security context (альтернатива инжекту Principal pr в параметрах)
        User user = userService.findByUsername(principal.getName());
        return "secured part of web service for user: " + user.getUsername() + " " + user.getEmail();
    }

    @GetMapping("/read_profile")
    public String pageForReadProfile(){
        return "read profile page:" ;
    }

    @GetMapping("/only_for_admins")
    public String pageOnlyForAdmins(){
        return "admins page";
    }



}
