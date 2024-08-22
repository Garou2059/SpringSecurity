package admin_user.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import admin_user.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
	
	User findByEmail(String email);
	 

}
