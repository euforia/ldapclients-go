package ldapclients

import (
	"fmt"
	"github.com/go-ldap/ldap"
	log "github.com/golang/glog"
)

const (
	AD_USER_FILTER        = "(objectClass=user)"
	AD_USER_ATTRIBUTE     = "sAMAccountName"
	AD_GROUP_ATTRIBUTE    = "memberOf"
	AD_GROUP_OBJECT_CLASS = "group"
)

type ActiveDirectoryClient struct {
	*LDAPClient
	// cache (if enabled)
	cache *CredentialsCache
}

func NewActiveDirectoryClient(ldapUri, bindDn, bindPass string, searchBase ...string) (ad *ActiveDirectoryClient, err error) {
	ad = &ActiveDirectoryClient{}
	ad.LDAPClient, err = NewLDAPClient(ldapUri, bindDn, bindPass, searchBase...)
	return
}

func (ad *ActiveDirectoryClient) Authenticate(username, password string) (err error) {
	if ad.cache != nil && ad.cache.CheckCreds(username, password) {
		return
	}

	var (
		userDn string
		userAD *ActiveDirectoryClient
	)

	if userDn, err = ad.GetUserDN(username); err != nil {
		return
	}

	if userAD, err = NewActiveDirectoryClient(ad.URI, userDn, password); err == nil && ad.cache != nil {
		// cache
		ad.cache.CacheCreds(NewCredentials(username, userDn, password))
	}
	userAD.Close()
	return
}

func (ad *ActiveDirectoryClient) EnableCaching(ttl int64) {
	if ad.cache == nil {
		ad.cache = NewCredentialsCache(ttl)
	}
}

func (ad *ActiveDirectoryClient) GetUserDN(username string) (userDN string, err error) {
	log.V(11).Infof("Search base: %s\n", ad.DefaultSearchBase)
	searchReq := &ldap.SearchRequest{
		BaseDN:     ad.DefaultSearchBase,
		Filter:     ad.getUserSearchFilter(username),
		Scope:      ldap.ScopeWholeSubtree,
		Attributes: []string{"distinguishedName"},
	}

	var rslt *ldap.SearchResult
	if rslt, err = ad.Search(searchReq); err != nil {
		return
	}
	if len(rslt.Entries) < 1 {
		err = fmt.Errorf("User not found: %s", username)
		return
	}
	// Double check user dn is actually returned
	if len(rslt.Entries[0].Attributes) < 1 || len(rslt.Entries[0].Attributes[0].Values) < 1 {
		err = fmt.Errorf("User DN attribute not found!")
		return
	}
	userDN = rslt.Entries[0].Attributes[0].Values[0]
	return
}

func (ad *ActiveDirectoryClient) getUserSearchFilter(samAccountName string) string {
	userFilter := fmt.Sprintf("(&(%s=%s)%s)",
		AD_USER_ATTRIBUTE, ldap.EscapeFilter(samAccountName), AD_USER_FILTER)

	log.V(11).Infof("Filter: %s\n", userFilter)

	return userFilter
}
