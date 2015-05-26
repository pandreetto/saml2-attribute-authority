package it.infn.security.saml.iam;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.AttributeQuery;

public interface AccessManager {

    public void init()
        throws AccessManagerException;

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query)
        throws AccessManagerException;

    public void close()
        throws AccessManagerException;

}