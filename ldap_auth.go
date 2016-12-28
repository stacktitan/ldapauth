package ldapauth

import (
	"errors"
	"fmt"

	ldap "gopkg.in/ldap.v2"
)

// LDAP holds configuration information to connect to an LDAP service
// and search for and authenticate users.
type LDAP struct {
	Label             string // Friendly string `Acme Inc.`
	Address           string // Host:Port `192.168.1.2:389`
	UID               string // 'sAMAAccountName'
	Method            string // 'plain', 'tls', 'ssl'
	Insecure          bool   // Use if using an self-signed certificate.
	BindDN            string // CN=some person,DC=example,DC=.com
	Password          string // Password to bind with, will be stored in plaintext.
	IsActiveDirectory bool   // Is an active directory environment.
	BaseSearch        string // Base search for users.
	UserFilter        string // Only allow users of this filter to login.
	AdminFilter       string // Users matching this filter will be made admins.
}

// Error messages.
const (
	BADPASSWORDERROR  = "authentication failed: bad password"
	USERNOTFOUNDEROR  = "authentication failed: username not found"
	DISABLEDUSERERROR = "authentication failed: user is disabled"
	BADFILTERERROR    = "server error: a filter returned multiple entrees"
)

// AuthUser is used to return information about an authenticated user.
type AuthUser struct {
	IsAdmin  bool
	Username string
}

// AttributeMapper is an interface to retreive and map attributes during authentication.
// Attributes should return a string of attributes to grab during an LDAP search.
// MapAttributes should map attributes from an Entry into the implementor.
type AttributeMapper interface {
	Attributes() []string
	MapAttributes(*ldap.Entry)
}

// Auth authenticates a username against the configured LDAP service.
// error will not be nil if authentication has failed.
func (l *LDAP) Auth(username, password string, mapper AttributeMapper) (*AuthUser, error) {
	conn, err := l.primaryBind()
	if err != nil {
		return nil, err
	}
	entry, err := l.findUser(conn, username, mapper.Attributes())
	if err != nil {
		return nil, err
	}

	isDisabled, err := l.isADAccountDisabled(conn, username)
	if err != nil {
		return nil, err
	}
	if isDisabled {
		return nil, errors.New(DISABLEDUSERERROR)
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, errors.New(BADPASSWORDERROR)
	}
	ok, err := l.isAdmin(conn, username)
	if err != nil {
		return nil, err
	}
	conn.Close()
	mapper.MapAttributes(entry)
	return &AuthUser{
		Username: entry.GetAttributeValue(l.UID),
		IsAdmin:  ok,
	}, nil
}

// Validate checks LDAP to ensure the user is still matching the user filter and is not disabled.
func (l *LDAP) Validate(username string) error {
	conn, err := l.primaryBind()
	if err != nil {
		return err
	}

	if _, err := l.findUser(conn, username, []string{}); err != nil {
		return err
	}
	if !l.IsActiveDirectory {
		return nil
	}
	isDisabled, err := l.isADAccountDisabled(conn, username)
	if err != nil {
		return err
	}
	if isDisabled {
		return errors.New(DISABLEDUSERERROR)
	}
	return nil
}

// primaryBind authenticates to the configured ldap server using
// the BindDN and Password.
func (l *LDAP) primaryBind() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error
	switch l.Method {
	case "plain":
		conn, err = ldap.Dial("tcp", l.Address)
	default:
		return nil, errors.New("server error: not implemented")
	}
	if err != nil {
		return nil, err
	}
	if err = conn.Bind(l.BindDN, l.Password); err != nil {
		return nil, err
	}
	return conn, nil
}

// isADAccountDisabled uses a special bitmask filter to check if an AD account is disabled.
// error is only returned if there is an error in the search filter.
func (l *LDAP) isADAccountDisabled(conn *ldap.Conn, username string) (bool, error) {
	disabledFilter := fmt.Sprintf("(&(%s=%s)(userAccountControl:1.2.840.113556.1.4.803:=2))", l.UID, ldap.EscapeFilter(username))
	search := ldap.NewSearchRequest(
		l.BaseSearch,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		disabledFilter,
		[]string{},
		nil)
	sr, err := conn.Search(search)
	if err != nil {
		return false, err
	}
	if len(sr.Entries) > 1 {
		return false, errors.New(BADFILTERERROR)
	}
	if len(sr.Entries) == 1 {
		return true, nil
	}
	return false, nil
}

// isAdmin uses the AdminFilter and the username to see if the user should be an admin.
// error is only returned if there is an error in the search filter.
func (l *LDAP) isAdmin(conn *ldap.Conn, username string) (bool, error) {
	usrAdminFilter := fmt.Sprintf("(&(%s=%s)%s)", l.UID, ldap.EscapeFilter(username), l.AdminFilter)
	search := ldap.NewSearchRequest(
		l.BaseSearch,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usrAdminFilter,
		[]string{},
		nil)
	sr, err := conn.Search(search)
	if err != nil {
		return false, err
	}
	if len(sr.Entries) > 1 {
		return false, errors.New(BADFILTERERROR)
	}
	if len(sr.Entries) == 1 {
		return true, nil
	}
	return false, nil
}

// findUser finds a user by the UseFilter. The UID will be available in the
// returned entree's attributes.
func (l *LDAP) findUser(conn *ldap.Conn, username string, attributes []string) (*ldap.Entry, error) {
	attributes = append(attributes, l.UID)
	usrFilter := fmt.Sprintf("(&(%s=%s)%s)", l.UID, ldap.EscapeFilter(username), l.UserFilter)
	search := ldap.NewSearchRequest(
		l.BaseSearch,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usrFilter,
		attributes,
		nil)
	sr, err := conn.Search(search)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) > 1 {
		return nil, errors.New(BADFILTERERROR)
	}
	if len(sr.Entries) == 1 {
		return sr.Entries[0], nil
	}
	return nil, errors.New(USERNOTFOUNDEROR)
}
