package it.infn.security.saml.iam;

import org.opensaml.saml2.core.AttributeQuery;

public interface AccessManager {

    public void init()
        throws AccessManagerException;

    public void authorizeAttributeQuery(AttributeQuery query)
        throws AccessManagerException;

    public void close()
        throws AccessManagerException;

}