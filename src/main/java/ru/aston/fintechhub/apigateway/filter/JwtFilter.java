package ru.aston.fintechhub.apigateway.filter;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtFilter implements GlobalFilter {

    @Value("${jwt.secret}")
    private final String jwtSecret;

    @Value("${authorization-page}")
    private final String authorizationPage;

    /**
     * Метод фильтра, который проверяет время жизни токена и принимает решение
     * о перенаправлении на страницу авторизации.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (exchange.getRequest().getPath().value().contains("authentication-service")) {
            return chain.filter(exchange);
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
        if (cookie != null) {
            try {
                Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)))
                        .build()
                        .parseClaimsJws(cookie.getValue());
                return chain.filter(exchange);
            } catch (JwtException ignored) { }
        }
        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().add("Location", authorizationPage);
        return exchange.getResponse().setComplete();
    }
}
