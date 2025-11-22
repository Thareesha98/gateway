package thareesha.campustalk.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class JwtUserFilter extends AbstractGatewayFilterFactory<JwtUserFilter.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    public JwtUserFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
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

                    // Adjust claim key according to your JWT (e.g. "userId" or "sub")
                    Object userId = claims.get("userId");
                    if (userId == null) {
                        userId = claims.getSubject(); // fallback
                    }

                    if (userId != null) {
                        var mutatedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", String.valueOf(userId))
                                .build();

                        exchange = exchange.mutate().request(mutatedRequest).build();
                    }

                } catch (Exception e) {
                    // If token is invalid, we simply don't inject header.
                    // Optionally: reject request with 401
                }
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {
        // empty. Can add future configurations if needed.
    }
}
