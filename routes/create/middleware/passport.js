import passport from 'passport';
import { Strategy as SamlStrategy } from 'passport-saml';
import User from '../models/User.js';
import jwt from 'jsonwebtoken';

// SAML Strategy configuration
const samlStrategy = new SamlStrategy({
  callbackUrl: process.env.SAML_CALLBACK_URL || 'http://localhost:7736/api/create/auth/saml/callback',
  entryPoint: process.env.SAML_ENTRY_POINT || 'http://localhost:8080/simplesaml/saml2/idp/SSOService.php',
  logoutUrl: process.env.SAML_LOGOUT_URL || 'http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php',
  logoutCallbackUrl: process.env.SAML_LOGOUT_CALLBACK_URL || 'http://localhost:7736/api/create/auth/logout/callback',
  issuer: process.env.SAML_ISSUER || 'tlef-create',
  cert: `-----BEGIN CERTIFICATE-----
MIIDmzCCAoOgAwIBAgIUCNQZvAiO2mtlriUBQZh4/onMTMgwDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAkJDMRIwEAYDVQQHDAlWYW5jb3V2
ZXIxDDAKBgNVBAoMA1VCQzELMAkGA1UECwwCSVQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yNTA4MDEwMTQwMzVaFw0zNTA3MzAwMTQwMzVaMF0xCzAJBgNVBAYTAkNB
MQswCQYDVQQIDAJCQzESMBAGA1UEBwwJVmFuY291dmVyMQwwCgYDVQQKDANVQkMx
CzAJBgNVBAsMAklUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCzqBUZiJtsh7a7q+SfkvrU9o80qocQnw3+5/NN5Puu
tAJThqSW19RM9DzrZNo61qltm3wmgWkeg/NzzNhQCMdpkbvsNMaSwzc7nRh4iqqU
i8TphsYJran45IB5jwJCX1cLff+Q2bzkMzn0wUhUBFSqZQQz/dmhNhjtu16h2ayz
D4c6+H0RqbFL7mPFu7tBq4p8FLcmOPUsAeF3pXsT/Jkx0N/bjplLm39lpxo9+SQH
u67sOfMtny+lhu3ZUKhXUhrxliIY+PQ7ZXnJ6ipruerBxUHraKu6TBD2PPuzdN2c
6Mt/imJ5gmTwovd20ZkuCNJ4IEhk56vdV6s9J1gAcAZZAgMBAAGjUzBRMB0GA1Ud
DgQWBBSyQdYnPlNOPm9Pnxj7+bIWuPysvDAfBgNVHSMEGDAWgBSyQdYnPlNOPm9P
nxj7+bIWuPysvDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBS
jvzJpgbqsnuYF8dYEvgNcI2wAiipqNomhq2ZYKdCJ+sylzqT5UJCUyp2k9JnSAma
yWjFPeq5wFaCVzTauxRB5b/9uZ3of3aHk3Z4zEUQo+Jipise4t4zLea9hN/EvTNE
dKJJth+JUFwAbPMNVeAJDr1OOEzNXEo3ltYX0H0yI7XDnJaojz8+N1/A7uXLSUm/
HI75JxVR/O3VWkJiijIXgkWLe1w76dS0R5bLQA+4aws9i6SDEEgKGyTK2aOkCeW1
tyBQ2TdO8xNgiXYCdRlGKKdeDNPq1Bgf9b5+ddRyy1IX6Vy7PwIcWKmhvZafVtVZ
Kq5xyHHPaADRIM/S/reS
-----END CERTIFICATE-----`,
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  disableRequestedAuthnContext: true,
  acceptedClockSkewMs: 5000,
  validateInResponseTo: false,
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: true,
  signatureAlgorithm: 'sha256'
}, async (profile, done) => {
  try {
    console.log('SAML Profile received:', JSON.stringify(profile, null, 2));
    
    // Extract user information from SAML profile
    const cwlId = profile.uid || profile.nameID;
    
    if (!cwlId) {
      return done(new Error('No CWL ID found in SAML profile'));
    }

    // Find or create user
    let user = await User.findOne({ cwlId });
    
    if (!user) {
      // Create new user
      user = new User({
        cwlId,
        password: 'saml-authenticated', // Placeholder - not used for SAML auth
        stats: {
          coursesCreated: 0,
          quizzesGenerated: 0,
          questionsCreated: 0,
          totalUsageTime: 0,
          lastActivity: new Date()
        }
      });
      await user.save();
    } else {
      // Update last login
      user.lastLogin = new Date();
      user.stats.lastActivity = new Date();
      await user.save();
    }

    return done(null, {
      _id: user._id,
      cwlId: user.cwlId,
      stats: user.stats
    });
  } catch (error) {
    console.error('SAML authentication error:', error);
    return done(error);
  }
});

passport.use('saml', samlStrategy);

// Serialize user to session
passport.serializeUser((user, done) => {
  done(null, user._id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select('-password');
    done(null, user);
  } catch (error) {
    done(error);
  }
});

export { passport, samlStrategy };