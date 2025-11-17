package renatius.jwtgatewayservice.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;


@Component
public class JWTUtil {

    private static final Logger LOGGER = LogManager.getLogger(JWTUtil.class);

    @Value("${JWT_SECRET_KEY}")
    private String jwtSecret;


    public boolean validateToken(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        try{
            Jwts.parser()
                    .verifyWith(generateSignKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return true;
        } catch (ExpiredJwtException e) {
            LOGGER.error("Expired JWT token");
            throw new ExpiredJwtException (e.getHeader(), e.getClaims(), e.getMessage()) {};
        }
        catch (UnsupportedJwtException e) {
            LOGGER.error("Unsupported JWT token");
            throw new UnsupportedJwtException("JWT token type is unsupported") {};
        }
        catch (MalformedJwtException e) {
            LOGGER.error("Malformed JWT token");
            throw new MalformedJwtException("JWT token format is invalid") {};
        }
        catch (SecurityException e) {
            LOGGER.error("Security exception");
            throw new SecurityException("JWT signature is invalid") {};
        }
    }

    private SecretKey generateSignKey(){
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String getUsernameFromToken(String token){
        Claims claims = Jwts.parser()
                .verifyWith(generateSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.get("username", String.class);
    }

    public String getUUIDFromToken(String token){
        Claims claims = Jwts.parser()
                .verifyWith(generateSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

}
