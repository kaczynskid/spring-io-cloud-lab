package auth

import groovy.transform.CompileStatic
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringApplication
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.SessionAttributes
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter

@SpringBootApplication
@Controller
@SessionAttributes('authorizationRequest')
@CompileStatic
class AuthenticationServiceApp extends WebMvcConfigurerAdapter {

    static void main(String[] args) {
        SpringApplication.run(AuthenticationServiceApp, args)
    }

    @Override
    void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController('/login').setViewName('login');
        registry.addViewController('/oauth/confirm_access').setViewName('authorize');
    }
}

@Configuration
@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
@CompileStatic
class LoginConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
            .loginPage('/login').permitAll()

        http.authorizeRequests()
            .anyRequest().authenticated()
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser('user').password('pass').roles('USER')
    }
}

@Configuration
@EnableAuthorizationServer
@CompileStatic
class OAuth2Config extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager

    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter() {
        KeyStoreKeyFactory keyFactory = new KeyStoreKeyFactory(new ClassPathResource('keystore.jks'), 'foobar'.chars)
        return new JwtAccessTokenConverter(keyPair: keyFactory.getKeyPair('test'))
    }

    @Override
    void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient('springio')
                .secret('secret')
                .authorizedGrantTypes('authorization_code', 'refresh_token', 'password')
                .scopes('openid');
    }

    @Override
    void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
            .authenticationManager(authenticationManager)
            .accessTokenConverter(jwtAccessTokenConverter())
    }

    @Override
    void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
            .tokenKeyAccess('permitAll()')
            .checkTokenAccess('isAuthenticated()')
    }
}
