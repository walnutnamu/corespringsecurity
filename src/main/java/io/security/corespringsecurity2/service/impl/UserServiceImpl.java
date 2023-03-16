package io.security.corespringsecurity2.service.impl;

import io.security.corespringsecurity2.domain.entity.Account;
import io.security.corespringsecurity2.repository.UserRepository;
import io.security.corespringsecurity2.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Slf4j
@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);

    }
}
