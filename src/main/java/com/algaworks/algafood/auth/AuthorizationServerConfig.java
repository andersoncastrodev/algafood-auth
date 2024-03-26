package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService detailsService;
	
	// AQUI NÃO É MAIS Http agora é Clients.
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		// EM MEMORIA - Sem usar o banco de dados.
		clients.inMemory()
		
				.withClient("algafood-web") // É UM CLIENTE
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write","read")
				
				.accessTokenValiditySeconds( 60 * 60 * 6) // TOKEN - Tempo para Gerar.
				
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // REFRESH TOKEN - Tempo para Gerar.
			
			.and()
			
				.withClient("foodnanalytics") // MAIS UM CLIENTE
				.secret(passwordEncoder.encode("food123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("write","read")	
				.redirectUris("http://aplicacao-cliente") // ADICIONANDO URI QUE VÃO SER PERMITIDAS
			
			.and()
			
				.withClient("faturamento") // MAIS UM CLIENTE
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write","read")
			
			.and()
			
			.withClient("checktoken")
				.secret(passwordEncoder.encode("check123"));
		}
	
	// USANDO PARA AUTENTICAR O Usuario e Senha ENVIADO 
	// PELO USUARIO FINAL as pessoas.
	// OBS: Só usando de for usar o fluxo "password" ou outros fluxo não precisa
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

		endpoints
		.authenticationManager(authenticationManager)
		
		.userDetailsService(detailsService)
		
		.reuseRefreshTokens(false); // NÃO ULTILIZAR O MESMO REFRESH TOKEN
	}
	
	// USANDO PARA VERFICAR SE O TOKEN E VALIDO
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		
		//Usando o "isAuthenticated()" sou obrigado a passar o usuario e senha no
		// cliente final.
		security.checkTokenAccess("isAuthenticated()");
		
		//Usando o permitAll() não sou obrigado para passar Usuario e Senha.
		security.checkTokenAccess("permitAll()");
	}

	
}
