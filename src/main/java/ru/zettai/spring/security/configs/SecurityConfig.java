package ru.zettai.spring.security.configs;

import net.bytebuddy.build.Plugin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import ru.zettai.spring.security.services.UserService;

import javax.sql.DataSource;

@EnableWebSecurity()
@EnableGlobalMethodSecurity(securedEnabled = true) //securedEnabled вместе в @Secured(Role) создаёт дополнительную защиту на методе

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    /*
        Указываем куда у пользователя есть доступ, а куда он попасть
        не может, а также указываем роли, права доступа, как вводится
        логин/пароль, выход пользователя из системы и т.д.
     */
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/authenticated/**").authenticated() // ес vли адрес так начинается, то пускаем только аутентифицированным пользователям
//                .antMatchers("/admin/**").hasAnyRole("ADMIN", "SUPERADMIN") // пускаем только пользователей с указанными ролями
                .antMatchers("/only_for_admins/**").hasRole("ADMIN")
                .antMatchers("/read_profile/**").hasAnyAuthority("READ_PROFILE")
                .and() //конец настройки доступа к областям
//                .httpBasic() //базовая аутентификация Springa
                .formLogin() //настраиваемая форма логинга (по умолчанию выдаётся учётка с логином user и паролем, который генерирует spring-security-starter
                .loginProcessingUrl("/myAddress") // здесь можно поменять адрес, от которого Spring будет ожидать получать данные при логинге (стандартно это "/login")
                .and()
                .logout().logoutSuccessUrl("/")
                .and()
                .csrf().disable(); // отключает дополнительную защиту информации в виде скрытого csrf токена,
        // который в ином случае необходимо вводить в post запросах (thymeleaf это делает автоматически); // указываем путь, куда пользователь попадёт после разлогинга
    }

//    @Bean
//    /*
//        InMemory
//        Метод для формирования и настройки пользователей
//        с указанием в данном случае через InMemoryUserDetailsManager,
//        что храниться данные о пользователях будут в памяти
//     */
//    public UserDetailsService users(){
//        UserDetails user = User.builder() //информация о пользователе
//                .username("user")
//                .password("{bcrypt}$2y$12$mnT37ZEUEwiRL63X51s1c.jjecR4lTFt2i2UWxhFa5oVWc8rQArYm")
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.builder() //информация о пользователе
//                .username("admin")
//                .password("{bcrypt}$2y$12$mnT37ZEUEwiRL63X51s1c.jjecR4lTFt2i2UWxhFa5oVWc8rQArYm")
//                .roles("USER","ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user, admin);
//    }


//    @Bean
//    /*
//        jdbcAuthentication
//        Настройка информации о пользователях, через использование базы данных
//        в стандартных таблицах со слабой настройкой. Нет необходимости создавать сущности для пользователей, ролей и аутентификаций.
//        При этом можно дополнительно докинуть несколько своих пользователей.
//        Соединение с БД идёт через jdbcUserDetailsManager и DataSource,
//     */
//    public JdbcUserDetailsManager users(DataSource dataSource){
        //также создаём базовых пользователей, но это не обязательная часть, можно использовать тех, которые уже есть в БД
//        UserDetails user = User.builder() //информация о пользователе
//                .username("user")
//                .password("{bcrypt}$2y$12$mnT37ZEUEwiRL63X51s1c.jjecR4lTFt2i2UWxhFa5oVWc8rQArYm")
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.builder() //информация о пользователе
//                .username("admin")
//                .password("{bcrypt}$2y$12$mnT37ZEUEwiRL63X51s1c.jjecR4lTFt2i2UWxhFa5oVWc8rQArYm")
//                .roles("USER", "ADMIN")
//                .build();
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        // Проверяем нет ли уже в БД таких пользователей (если таковые имеются, а проверки нет, то вылетит ошибка)
//        if(jdbcUserDetailsManager.userExists(user.getUsername())){
//            jdbcUserDetailsManager.deleteUser(user.getUsername());
//        }
//        if(jdbcUserDetailsManager.userExists(admin.getUsername())){
//            jdbcUserDetailsManager.deleteUser(admin.getUsername());
//        }
//
//        jdbcUserDetailsManager.createUser(user);
//        jdbcUserDetailsManager.createUser(admin);
//        return jdbcUserDetailsManager;
//    }

    /*
        Нужен для получения зашифрованного пароля из простого (plain text), который мы вбиваем
        в форму логинга
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    /*
        daoAuthenticationProvider
        Настраиваемое создание пользователей на основе базы данных через
        daoAuthenticationProvider, в который необходимо передать passwordEncoder
        для шифрования пароля и информацию о пользователях через userDetailService,
        в который мы передаём экземпляр созданного нами user service
     */
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        authenticationProvider.setUserDetailsService(userService);
        return authenticationProvider;
    }

}
