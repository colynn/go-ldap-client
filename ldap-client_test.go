package ldap

import (
	"log"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	client := &Client{
		Base:               "ou=example,dc=example,dc=com",
		Host:               "ldap.example.cn",
		Port:               389,
		UseSSL:             false,
		BindDN:             "ldap@example.com",
		BindPassword:       "bindpassword",
		UserFilter:         "(samaccountname=%s)",
		GroupFilter:        "(memberUid=%s)",
		Attributes:         []string{"givenName", "sn", "mail", "uid"},
		SkipTLS:            false,
		ServerName:         "ldap.example.cn",
		InsecureSkipVerify: true,
	}
	defer client.Close()

	ok, user, err := client.Authenticate("username", "password")
	if err != nil {
		log.Fatalf("Error authenticating user %s: %+v", "username", err)
	}
	if !ok {
		log.Fatalf("Authenticating failed for user %s", "username")
	}
	log.Printf("User: %+v", user)
}

func TestFindUser(t *testing.T) {
	client := &Client{
		Base:               "OU=example,DC=example,DC=com",
		Host:               "ldap.example.com",
		Port:               389,
		UseSSL:             false,
		BindDN:             "ldap@example.com",
		BindPassword:       "bindpassword",
		UserFilter:         "(uid=%s)",
		GroupFilter:        "(memberUid=%s)",
		Attributes:         []string{"givenName", "sn", "mail", "uid", "sAMAccountName"},
		SkipTLS:            true,
		ServerName:         "ldap.example.com",
		InsecureSkipVerify: true,
	}
	defer client.Close()

	user, err := client.FindUser("username")
	if err != nil {
		log.Fatalf("Error get user : %s", err.Error())
	}

	log.Printf("User: %+v", user)
}

func TestGetGroupsOfUser(t *testing.T) {
	client := &Client{
		Base:         "dc=example,dc=com",
		Host:         "ldap.example.cn",
		Port:         389,
		GroupFilter:  "(memberUid=%s)",
		BindDN:       "ldap@example.com",
		BindPassword: "bindpassword",
	}
	defer client.Close()
	groups, err := client.GetGroupsOfUser("username")
	if err != nil {
		log.Fatalf("Error getting groups for user %s: %+v", "username", err)
	}
	log.Printf("Groups: %+v", groups)
}
