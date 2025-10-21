package renatius.jwtgatewayservice.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;


@Component
public class JWTUtil {

    private static final Logger LOGGER = LogManager.getLogger(JWTUtil.class);

    private final String jwtSecret;

    public JWTUtil(@Value("${JWT_SECRET}") String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public boolean validateToken(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        try{
            Jwts.parser()
                    .verifyWith(generateSignKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return true;
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException (e.getHeader(), e.getClaims(), e.getMessage()) {};
        }
        catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException("JWT token type is unsupported") {};
        }
        catch (MalformedJwtException e) {
            throw new MalformedJwtException("JWT token format is invalid") {};
        }
        catch (SecurityException e) {
            throw new SecurityException("JWT signature is invalid") {};
        }
    }

    private SecretKey generateSignKey(){
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
}
