package renatius.jwtgatewayservice.jwt.filters;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class InternalGatewayFilter implements GatewayFilter {

    @Value("${X_SECRET_GATEWAY_HEADER}")
    private String internalKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header("X-Internal-Key", internalKey)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }
}

