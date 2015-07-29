package ldapclients

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	//log "github.com/golang/glog"
	"strings"
)

type LDAPClient struct {
	*ldap.Conn
	// Default search base
	DefaultSearchBase string
	// ldap uri
	URI string
}

func NewLDAPClient(ldapUri, bindDn, bindPass string, searchBase ...string) (ad *LDAPClient, err error) {
	protoHostPort := strings.Split(ldapUri, "://")
	if len(protoHostPort) != 2 {
		err = fmt.Errorf("Invalid LDAP URI: %s", ldapUri)
		return
	}

	ad = &LDAPClient{URI: ldapUri}

	if protoHostPort[0] == "ldaps" {
		ad.Conn, err = ldap.DialTLS("tcp", protoHostPort[1], &tls.Config{InsecureSkipVerify: true})
	} else {
		//no ssl port 389
		ad.Conn, err = ldap.Dial("tcp", protoHostPort[1])
	}
	if err != nil {
		return
	}

	if len(searchBase) > 0 {
		ad.DefaultSearchBase = searchBase[0]
	}
	err = ad.Bind(bindDn, bindPass)
	return
}
