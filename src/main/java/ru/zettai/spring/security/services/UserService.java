package ru.zettai.spring.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zettai.spring.security.entities.Role;
import ru.zettai.spring.security.entities.User;
import ru.zettai.spring.security.repositories.UserRepository;

import java.util.Collection;
import java.util.stream.Collectors;

/*
    Задачей данного сервиса является по имени пользователя предоставить саму сущность пользователя
 */
@Service
public class UserService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    @Transactional
    /*
        Преобазуем инфу о пользователе, которого вытащили из базы данных
        через репозиторий в инфу, которая дальше может быть использована
        Spring Security, а именно имя пользователя, его пароль и коллекцию ауторити

        @Transactional нужна для того, чтобы объединить все операции этого метода в одну транзакцию.
        Это необходимо, чтобы когда мы вытаскиваем пользотвателя через репозиторий
        у нас не возникало исключение из-за ленивой инициализации у поля roles (для One-to-Many используется
        Lazy fetch type)
     */
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User currentUser = findByUsername(username);
        if(currentUser == null){
            throw new UsernameNotFoundException(String.format("User %s not found!", username));
        }

        return new org.springframework.security.core.userdetails.User(
                currentUser.getUsername(),
                currentUser.getPassword(),
                mapRolesToAuthorities(currentUser.getRoles()));
    }

    //Метод для преобразования коллекции ролей к коллекции ауторити, ибо userdetails нуждается в коллекции ауторити
    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles){
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }
}
