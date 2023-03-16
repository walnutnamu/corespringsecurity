package io.security.corespringsecurity2.security.service;

import io.security.corespringsecurity2.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        // User 객체로 인증 처리
        super(account.getUsername(), account.getPassword(), authorities);

        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
