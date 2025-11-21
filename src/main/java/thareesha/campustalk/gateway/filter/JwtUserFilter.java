package thareesha.campustalk.gateway.filter;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class JwtUserFilter extends AbstractGatewayFilterFactory<Object> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                try {
                    String token = authHeader.substring(7);

                    Claims claims = Jwts.parserBuilder()
                            .setSigningKey(jwtSecret.getBytes())
                            .build()
                            .parseClaimsJws(token)
                            .getBody();

                    String userId = claims.get("userId", String.class);

                    if (userId != null) {
                        // Inject into downstream
                        exchange = exchange.mutate()
                                .request(req -> req.headers(
                                        h -> h.set("X-User-Id", userId)))
                                .build();
                    }

                } catch (Exception ignored) {}
            }

            return chain.filter(exchange);
        };
    }
}
