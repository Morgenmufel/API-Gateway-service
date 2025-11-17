package renatius.jwtgatewayservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import renatius.jwtgatewayservice.jwt.filters.InternalGatewayFilter;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    private final InternalGatewayFilter internalGatewayFilter;

    @Bean
    public RouteLocator customRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth-service", r -> r
                        .path("/auth/**")
                        .and()
                        .method("POST", "GET", "OPTIONS", "PUT")
                        .uri("http://auth-service:8081"))
                .route("image-service", r -> r
                        .path("/api/**")
                        .and()
                        .method("POST", "GET", "OPTIONS", "PUT", "DELETE")
                        .filters(f -> f.filter(internalGatewayFilter))
                        .uri("http://image-service:8082"))
                .build();
    }
}
