package auth

// signupURL, proxyHost := web.CreateSignupLink(client, token)

//CreateUserWithoutOTP creates an account with the provided password and deletes the token afterwards.
import (
	"fmt"
	"net/url"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
)

// CreateInviteToken invites a user
func (s *AuthServer) CreateInviteToken(userInvite services.UserInvite) (services.UserToken, error) {
	if err := userInvite.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	if userInvite.ExpiresIn > defaults.MaxSignupTokenTTL {
		return nil, trace.BadParameter("failed to create a token: maximum token TTL is %v hours", int(defaults.MaxSignupTokenTTL/time.Hour))
	}

	if userInvite.ExpiresIn == 0 {
		userInvite.ExpiresIn = defaults.SignupTokenTTL
	}

	// Validate that requested roles exist.
	for _, role := range userInvite.Roles {
		if _, err := s.GetRole(role); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	userToken, err := s.createUserToken(services.UserTokenTypeInvite, userInvite.Name, userInvite.ExpiresIn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = s.DeleteUserTokens(services.UserTokenTypeInvite, userInvite.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.UpsertUserInvite(userInvite)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = s.CreateUserToken(userToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s.GetUserToken(userToken.GetName())
}

func (s *AuthServer) createUserToken(tokenType string, name string, ttl time.Duration) (services.UserToken, error) {
	token, err := utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// This OTP secret and QR code are never actually used. The OTP secret and
	// QR code are rotated every time the signup link is show to the user, see
	// the "GetSignupTokenData" function for details on why this is done. We
	// generate a OTP token because it causes no harm and makes tests easier to
	// write.
	accountName := name + "@" + s.AuthServiceName
	_, otpQRCode, err := s.initializeTOTP(accountName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenURL, _ := s.createSignupLink(token)
	userToken := services.NewUserToken(token)
	userToken.Metadata.SetExpiry(s.clock.Now().UTC().Add(ttl))
	userToken.Spec.Type = services.UserTokenTypeInvite
	userToken.Spec.URL = tokenURL
	userToken.Spec.User = name
	userToken.Spec.QRCode = otpQRCode
	userToken.Spec.Created = s.clock.Now().UTC()
	return &userToken, nil
}

// CreateSignupToken creates one time token for creating account for the user
// For each token it creates username and otp generator
//func (s *AuthServer) CreateSignupToken(userv1 services.UserV1, ttl time.Duration) (string, error) {
//	clusterConfig, err := s.GetClusterConfig()
//	if err != nil {
//		return "", trace.Wrap(err)
//	}
//	if clusterConfig.GetLocalAuth() == false {
//		s.emitNoLocalAuthEvent(userv1.V2().GetName())
//		return "", trace.AccessDenied(noLocalAuth)
//	}
//
//	user := userv1.V2()
//	if err := user.Check(); err != nil {
//		return "", trace.Wrap(err)
//	}
//
//	if ttl > defaults.MaxSignupTokenTTL {
//		return "", trace.BadParameter("failed to invite user: maximum signup token TTL is %v hours", int(defaults.MaxSignupTokenTTL/time.Hour))
//	}
//
//	// make sure that connectors actually exist
//	for _, id := range user.GetOIDCIdentities() {
//		if err := id.Check(); err != nil {
//			return "", trace.Wrap(err)
//		}
//		if _, err := s.GetOIDCConnector(id.ConnectorID, false); err != nil {
//			return "", trace.Wrap(err)
//		}
//	}
//
//	for _, id := range user.GetSAMLIdentities() {
//		if err := id.Check(); err != nil {
//			return "", trace.Wrap(err)
//		}
//		if _, err := s.GetSAMLConnector(id.ConnectorID, false); err != nil {
//			return "", trace.Wrap(err)
//		}
//	}
//
//	// TODO(rjones): TOCTOU, instead try to create signup token for user and fail
//	// when unable to.
//	_, err = s.GetPasswordHash(user.GetName())
//	if err == nil {
//		return "", trace.BadParameter("user '%s' already exists", user.GetName())
//	}
//
//	token, err := utils.CryptoRandomHex(TokenLenBytes)
//	if err != nil {
//		return "", trace.Wrap(err)
//	}
//
//	// This OTP secret and QR code are never actually used. The OTP secret and
//	// QR code are rotated every time the signup link is show to the user, see
//	// the "GetSignupTokenData" function for details on why this is done. We
//	// generate a OTP token because it causes no harm and makes tests easier to
//	// write.
//	accountName := user.GetName() + "@" + s.AuthServiceName
//	otpKey, otpQRCode, err := s.initializeTOTP(accountName)
//	if err != nil {
//		return "", trace.Wrap(err)
//	}
//
//	// create and upsert signup token
//	tokenData := services.SignupToken{
//		Token:     token,
//		User:      userv1,
//		OTPKey:    otpKey,
//		OTPQRCode: otpQRCode,
//	}
//
//	if ttl == 0 || ttl > defaults.MaxSignupTokenTTL {
//		ttl = defaults.SignupTokenTTL
//	}
//
//	err = s.UpsertSignupToken(token, tokenData, ttl)
//	if err != nil {
//		return "", trace.Wrap(err)
//	}
//
//	log.Infof("[AUTH API] created the signup token for %q", user)
//	return token, nil
//}

func formatUserTokenURL(advertiseURL string, path string) (string, error) {
	u, err := url.Parse(advertiseURL)
	if err != nil {
		return "", trace.Wrap(err)
	}

	u.RawQuery = ""
	u.Path = path

	return u.String(), nil
}

// CreateSignupLink generates and returns a URL which is given to a new
// user to complete registration with Teleport via Web UI
func (s *AuthServer) createSignupLink(token string) (string, string) {
	proxyHost := "<proxyhost>:3080"
	proxies, err := s.GetProxies()
	if err != nil {
		log.Errorf("Unable to retrieve proxy list: %v", err)
	}

	if len(proxies) > 0 {
		proxyHost = proxies[0].GetPublicAddr()
		if proxyHost == "" {
			proxyHost = fmt.Sprintf("%v:%v", proxies[0].GetHostname(), defaults.HTTPListenPort)
			log.Debugf("public_address not set for proxy, returning proxyHost: %q", proxyHost)
		}
	}

	u := &url.URL{
		Scheme: "https",
		Host:   proxyHost,
		Path:   "web/newuser/" + token,
	}
	return u.String(), proxyHost
}
