package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession session){
        //세션에도 저장이 된다. -> HttpSession session
        //세션에서도 참조가 가능
        SecurityContext attribute = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        //해당 키로꺼내오는 것도 가능하다.
        //Object attribute 이렇게 반환이 되는데 캐스팅해준다.
        Authentication authentication1 = attribute.getAuthentication();
        //이렇게 반환.

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //최종적으로 인증에 성공한 객체를 담은 구현체


        return "home";
    }

    @GetMapping("/thread")
    public String thread(HttpSession session){
        //메인스레드하고 자식스레드 간에 시큐리티 컨텍스트 공유가 되지 않는다.
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            }
        }).start();


        return "thread";
    }

    /*
        1.  의존성을 추가하면 스프링 시큐리티가 초기화 작업 , 보안 설정을 한다.
            별도의 설정이나 구현을 하지 않아도 웹 기능 보안이 이루어진다.
            처음 뜨는 id는 user 를 적어주며 비밀번호는 Using generated security password: a8d949d3-db8a-4791-af64-4f8bb84476c1 (기본 계정으로 한 개만 제공)

            인증 방식에는 폼로그인 방식과 httpBasic 로그인 방식을 제공한다.
            + 부수적으로 DB와 연동도 하며 권한도 추가하고 계정도 추가해야한다. 그것을 학습한다.

            WebSecurityConfigurerAdapter -> 웹 보안 기능을 초기화하면서 가장 기본적인 설정을 해준다.
            HttpSecurity 클래스는 세부적인 보안 기능을 설정할 수 있는 API 제공을 한다. (인가, 인증 API)

            SecurityConfig 라는 클래스를 만들것이다 -> 사용자 정의 보안 설정 클래스라고 칭하고 WebSecurityConfigurerAdapter 를 상속받는다.
            그리고 오버라이드 configure 라는 메서드를 해주고
            그러면 파라미터로 있는 HttpSecurity 클래스를 사용해서 사용할 수 있는 API 로 구현을 한다.
            인가, 인증 API 에 대해서 공부한다.


     */

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }


    //antmatcher-----------------------------------------------------------------

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String adminAndSys(){
        return "admin And sys";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

}
