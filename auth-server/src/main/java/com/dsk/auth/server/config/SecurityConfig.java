package com.dsk.auth.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	/**
	 * 完整流程说明：
	 * 1.用户访问授权端点 如 /oauth2/authorize,如果未登录，spring security 检查 Accept头
	 * 如果是 text/html 重定向到 /login页面
	 * 如果是其他类型（如API请求）返回401 Unauthorized
	 */

	@Bean
	@Order(1)  // 优先级高于默认过滤器链
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // 匹配授权服务器端点
				.with(authorizationServerConfigurer, (authorizationServer) ->
						authorizationServer
								.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
				)
				.authorizeHttpRequests(authorize -> authorize
						.anyRequest().authenticated()
				)
				.exceptionHandling((exceptions) -> exceptions
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
						)
				)
				//通过 oauth2ResourceServer() 方法声明当前应用为 OAuth2 资源服务器，负责验证访问令牌（Access Token）并保护资源
				//客户端访问授权服务器通过 /userinfo 接口获取用户信息时需要验证token信息的正确与否，此时/userinfo可以理解为受保护的资源
				//所以下面的代码必须添加，否则无法实现客户端服务和授权服务器正常流程的流转
				.oauth2ResourceServer((resourceServer) -> resourceServer
						.jwt(Customizer.withDefaults()))
				.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()));

		return http.build();
	}
    /**
	 * 配置用于身份验证的Spring Security过滤器链
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults());

		return http.build();
	}
    /**
	 * 功能：创建一个内存中的用户存储，定义了一个用户名为 user、密码为 password、角色为 USER 的账户。
	 * 适用场景：适用于测试环境或简单应用，生产环境需改用数据库存储。
	 *
	 */
	@Bean
	public UserDetailsService userDetailsService() {
		// User.withDefaultPasswordEncoder() 使用默认的密码编码器
		//withDefaultPasswordEncoder() 实际使用 DelegatingPasswordEncoder，默认编码方式为 BCrypt
		// 此方法会将密码明文转换为哈希值，但代码中直接暴露明文密码（如 password("password")）,生产环境不推荐使用
		UserDetails userDetails = User.withDefaultPasswordEncoder()
				.username("yf")
				.password("123456")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}
    /**
	 * 该 Bean 定义了一个 OAuth2/OpenID Connect 客户端，
	 * 用于在 Spring Authorization Server 中注册客户端信息，
	 * 支持 授权码模式（Authorization Code） 和 OpenID Connect 协议。
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("oidc-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://spring-oauth-client:9001/login/oauth2/code/messaging-client-oidc")
				//我们暂时还没有客户端服务，以免重定向跳转错误导致接收不到授权码
				.redirectUri("http://www.baidu.com")
				.postLogoutRedirectUri("http://127.0.0.1:8080/")
				// 设置客户端权限范围
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				// 客户端设置用户需要确认授权
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(120))  // Access Token 过期时间
						.refreshTokenTimeToLive(Duration.ofDays(7))      // Refresh Token 过期时间
						.build())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}
    /**
	 * 该配置用于生成 RSA 密钥对，
	 * 并构建 JWK Set（JSON Web Key Set），
	 * 供 Spring Authorization Server 签发和验证 JWT 格式的令牌
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}
    // 生成 RSA 密钥对（公钥 + 私钥）
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
    /**
	 * 该配置定义了一个 JwtDecoder Bean，用于 解析和验证 JWT 令牌，通常在 资源服务器 中使用。
	 * OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
	 * 通过授权服务器的 JWKSource（公钥集）创建解码器，确保资源服务器能验证授权服务器签发的令牌
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
    /**
	 * AuthorizationServerSettings 用于定义 OAuth2 授权服务器的元数据，
	 * 包括端点的访问路径和签发者（Issuer）信息。此配置直接影响令牌的生成、
	 * 验证及客户端如何与授权服务器交互
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}