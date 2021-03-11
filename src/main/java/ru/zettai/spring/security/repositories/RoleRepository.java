package ru.zettai.spring.security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.zettai.spring.security.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository <Role, Long> {

}
