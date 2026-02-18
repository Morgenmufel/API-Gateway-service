package renatius.jwtgatewayservice.jwt.filters;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import renatius.jwtgatewayservice.jwt.JWTUtil;

import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class AuthFilter implements WebFilter {

    private final JWTUtil jwtUtil;

    private static final Logger LOGGER = LogManager.getLogger(AuthFilter.class);

    private static final String[] WHITELIST = {
            "/auth/register",
            "/auth/login",
            "/auth/refresh-token",
            "/auth/reset-password",
            "/auth/forgot-password"
    };

    @Value("${FRONTEND_URL}")
    private String frontendUrl;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequest().getMethod().name())) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/api/images/") && path.endsWith("/content")) {
            return chain.filter(exchange);
        }
        for (String open : WHITELIST) {
            if (path.startsWith(open)) {
                return chain.filter(exchange);
            }
        }
        String authHead = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHead == null || !authHead.startsWith("Bearer ")) {
            LOGGER.error("Wrong Authorization header value");
            return writeUnauthorized(exchange, "Missing or invalid Authorization header");
        }
        String token = authHead.substring(7).trim();
        try {
            if (!jwtUtil.validateToken(token)) {
                LOGGER.error("Invalid token");
                return writeUnauthorized(exchange, "Invalid token");
            }
            String userId = jwtUtil.getUUIDFromToken(token);
            String username = jwtUtil.getUsernameFromToken(token);
            exchange = exchange.mutate()
                    .request(builder -> builder
                            .header("X-User-Id", userId)
                            .header("X-Username", username)
                    )
                    .build();
        } catch (ExpiredJwtException e) {
            LOGGER.error("Expired JWT token");
            return writeUnauthorized(exchange, "Jwt token expired");
        }
        catch (UnsupportedJwtException e) {
            LOGGER.error("Unsupported JWT token");
            return writeUnauthorized(exchange,"JWT token type is unsupported");
        }
        catch (MalformedJwtException e) {
            LOGGER.error("Malformed JWT token");
            return writeUnauthorized(exchange,"JWT token format is invalid");
        }
        catch (SecurityException e) {
            LOGGER.error("Security exception");
            return writeUnauthorized(exchange,"JWT signature is invalid") ;
        }
        return chain.filter(exchange);

    }

    public Mono<Void> writeUnauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("Content-Type", "application/json");
        exchange.getResponse().getHeaders().set("Access-Control-Allow-Origin", frontendUrl);
        exchange.getResponse().getHeaders().set("Access-Control-Allow-Credentials", "true");
        String body = String.format("{\"error\":\"%s\"}", message);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(bytes))
        );
    }
}
