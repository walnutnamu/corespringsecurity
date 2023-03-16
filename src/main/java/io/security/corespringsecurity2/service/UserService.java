package io.security.corespringsecurity2.service;

import io.security.corespringsecurity2.domain.entity.Account;

public interface UserService {

    void createUser(Account account);
}
