# ldapauth
[![](https://godoc.org/github.com/stacktitan/ldapauth?status.svg)](http://godoc.org/github.com/stacktitan/ldapauth)

LDAP authentication made easier. Borrows some high level details from Gitlab.

### Example
```go
package main

type User struct {
    Username string
    FirstName string
    IsAdmin bool
}

func (u *User) Attributes() []string{
    return []string{"givenName"}
}

func (u *User) MapAttributes(entry *ldap.Entry) {
    u.FirstName = entry.GetAttributeValue("givenName")
}

func main() {
    viper.AutomaticEnv()
    viper.SetConfigName("ldap")
    viper.AddConfigPath(".")
    // See documentation for details.
    ldp := &ldapauth.LDAP{
	    Address:           viper.GetString("ldap.address"),
    	UID:               viper.GetString("ldap.uid"),
	    Method:            viper.GetString("ldap.method"),
	    BindDN:            viper.GetString("ldap.bind_dn"),
	    Password:          viper.GetString("ldap.password"),
	    IsActiveDirectory: viper.GetBool("ldap.is_active_directory"),
	    BaseSearch:        viper.GetString("ldap.base_search"),
	    UserFilter:        viper.GetString("ldap.user_filter"),
	    AdminFilter:       viper.GetString("ldap.admin_filter"),
    }

    var user User
    a, err := ldp.Auth("alice.smith", "password1", &user)
    if err != nil {
        panic(err) // Authentication failed.
    }
    user.Username = a.Username
    user.IsAdmin = a.IsAdmin

    fmt.Println(user.FirstName) // Will be attribute of givenName

    // Sometime later...
    if err := ldp.Validate(user.Username); err != nil {
        panic(err) // User is disabled or not in UserFilter.
    }
}

```
