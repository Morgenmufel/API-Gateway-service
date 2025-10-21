package renatius.jwtgatewayservice.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class AuthFilter implements WebFilter {

    private final JWTUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        if (path.equals("/auth/login") ||
            path.equals("/auth/register") ||
            path.equals("/auth/refresh-token")) {
            return chain.filter(exchange);
        }

        String authHead = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHead == null || !authHead.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String token = authHead.substring(7).trim();


        try {
            if (!jwtUtil.validateToken(token)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        } catch (ExpiredJwtException e) {
            return writeUnauthorized(exchange, "Jwt token expired");
        }
        catch (UnsupportedJwtException e) {
            return writeUnauthorized(exchange,"JWT token type is unsupported");
        }
        catch (MalformedJwtException e) {
            return writeUnauthorized(exchange,"JWT token format is invalid");
        }
        catch (SecurityException e) {
            return writeUnauthorized(exchange,"JWT signature is invalid") ;
        }
        return chain.filter(exchange);

    }

    public static Mono<Void> writeUnauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("Content-Type", "application/json");
        String body = String.format("{\"error\":\"%s\"}", message);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(bytes))
        );
    }
}
