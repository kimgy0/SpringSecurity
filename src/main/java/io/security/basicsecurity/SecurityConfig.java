package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration      // 설정파일이기 때문에 적어줘야한다.
//@EnableWebSecurity  // 이 어노테이션은 @Import({WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class, HttpSecurityConfiguration.class})
                    //등과 같이 설정을 해주는 어노테이션이기 때문에 적어줘야한다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
                          //어떤 요청에도 인증을 할 수 있게 해야한다. 라는 설정
        http.formLogin() // 기본적으로 폼로그인을 할 수 있게 설정한다.
        /*
         *   하지만 초기 설정과 똑같은 방식이라서 랜덤으로 나온 패스워드와 user 라는 아이디 값으로 로그인해야 하는데
         *   이렇게 말고 다른 아이디와 비밀번호로 설정해주고 싶으면 application.yml 에
         *   spring.security.user.name=user
         *   spring.security.user.password=user
         *   설정하면 user/user 로 로그인을 해줄 수 있다.
         */
        //        .loginPage("/loginPage")// 우리가 생성한 로그인 페이지로 정의한다. -> 단, 이경로는 로그인을 안해도 접근이 가능하도록 해야한다.
                .defaultSuccessUrl("/") // 로그인 성공시 이 페이지로 이동한다.
                .failureUrl("/login") // 실패 후에 이동하는 페이지.
                .usernameParameter("userId") // 파라미터 이름의 정의
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc") // 로그인을 처리해주는 action url 을 적어준다 (폼태그의 액션)
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request,
                                                        HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication "+ authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request,
                                                        HttpServletResponse response,
                                                        AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // 로그인 페이지도 현재 스프링 시큐리티가 로그인을 안하면 무조건 막게 되어있다. 그러므로 permitAll 을 써서 그런 이상상태를 막아주자.




        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");

        //remember-me function
        http.rememberMe()
//        쿠키를 가지고 서버에 접근하게 되는것.
//                세션 만료후 웹브라우저가 종료되어도 만료일을 정해서 쿠키를 가지고 자동로그인 설정하기 같은 기능을 사용한다.
//        remember me 쿠키를 가지고 서버에 접근하는 경우 서버는 쿠키를 확인하고 토큰 기반의 인증을 하게 된다. 토큰 검증 후 사용자는 로그인을 한다.
//        세가지 라이프사이클에
//        - 인증 성공 ( remember-me 쿠키 설정)
//                - 인증 실패 쿠키가 존재하면 쿠키 무효화한다.
//                - 로그아웃도 똑같은 역할을 한다.
                .rememberMeParameter("remember")
                //rememberMe 기능을 이용할 체크박스의 name 속성
                .tokenValiditySeconds(3600)
                //디폴트는 14일동안 유지 가능하다.
                .alwaysRemember(false)
                //리멤버 기능이 활성화 되어지지 않아도(체크박스에 설정되어지지 않아도)
                //true 를 성정하면 로그인이 되는 순간 rememberMe 기능이 활성
                .userDetailsService(userDetailsService);
                //시스템에 사용자 계정을 조회할 때 쓰는 클래스를 인자로.

        /*
            기존에 기능을 쓰지 않으면 jsession id를 삭제해주면 다시 로그인해야하는데
            이기능을 적용하게 되면 jession id 를 삭제해도 쿠키가 존재하기 때문에
            인증에 성공하게 된다. -> 쿠키에는 username, password, 만료일 등등이 존재한다.

            인증에 성공할 경우 jsessionid 를 가지고 서버가 클라이언트 jsession 를 꺼내고
            그 세션에 시큐리티 컨텍스트가 있고 그 안에 인증에 성공한 인증객체가 존재.
            이렇게 매칭 후 스프링이 인증된 객체가 맞는지 확인.
            클라이언트 쿠키엔 jsessionId 가 존재. -> 서버도 가지고있음 세션아이디를
         */
    }
}
