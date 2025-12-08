package thareesha.campustalk.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;

import org.springframework.stereotype.Component;
import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.Key;

@Component
public class JwtUserFilter extends AbstractGatewayFilterFactory<JwtUserFilter.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private final WebClient webClient;

    public JwtUserFilter() {
        super(Config.class);
        this.webClient = WebClient.builder().build();
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                try {
                    String token = authHeader.substring(7);

                    Key hmacKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
                    Claims claims = Jwts.parserBuilder()
                            .setSigningKey(hmacKey)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();

                    String email = claims.getSubject();
                    System.out.println("JWT FILTER: extracted email = " + email);

                    // 🔥 CALL MONOLITH to convert email → userId
                    return webClient.get()
                            .uri("http://localhost:8081/api/users/id-by-email?email=" + email)
                            .retrieve()
                            .bodyToMono(Long.class)
                            .defaultIfEmpty(-1L)
                            .flatMap(userId -> {

                                System.out.println("JWT FILTER: resolved userId = " + userId);

                                var mutated = exchange.getRequest().mutate()
                                        .header("X-User-Id", String.valueOf(userId))
                                        .build();

                                return chain.filter(exchange.mutate().request(mutated).build());
                            });

                } catch (Exception e) {
                    System.out.println("JWT FILTER ERROR: " + e.getMessage());
                }
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {}
}
