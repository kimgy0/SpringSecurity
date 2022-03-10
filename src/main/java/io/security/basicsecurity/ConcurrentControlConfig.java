package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ConcurrentControlConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();

        http.formLogin();

        http.sessionManagement()
                .maximumSessions(1) // -> 세션의 최대허용 가능한 갯수 (-1 은 무제한 로그인을 세션 허용한다는 뜻이다.)
                .maxSessionsPreventsLogin(false) // true : 동시로그인을 아예 차단한다. , default : false -> 세션을 생성하지 못하게하는 것. 2번째 전략.
                /*
                 true 로 하면 동시로그인을 아예 차단하고
                 false 로 하고 로그인을 두개다 하면 전용 필터가 접근해서 세션이 만료되었는지 안되었는지 만료시킴
                 */
                .expiredUrl("/expired"); // 세션이 만료된 경우 이동할 페이지

        //동시성 이슈
        http.sessionManagement().sessionFixation().changeSessionId(); //세션 아이디만 변하게함. //서블릿 3.1 이상
        // 기본 값
        // none -> 세션고정공격에 당함.
        // migrateSession : 세션이 새로 생성되고 세션아이디가 바뀜 -> 서블릿 3.1 이하에서 작동하도록

        // newSession : 이전에 세션에서 설정한 속성의 값들을 사용하지 못함. 새로 세팅해야됨
    }
}
