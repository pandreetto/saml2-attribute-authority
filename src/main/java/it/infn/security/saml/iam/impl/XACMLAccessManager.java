package it.infn.security.saml.iam.impl;

import java.security.Principal;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.AttributeQuery;

import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;

public class XACMLAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(XACMLAccessManager.class.getName());

    public void init()
        throws AccessManagerException {

    }

    public void close()
        throws AccessManagerException {

    }

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query)
        throws AccessManagerException {

        Principal tmpp = subject.getPrincipals().iterator().next();
        logger.info("Authorized query for " + tmpp.getName());
        return new AccessConstraints();
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {
        return new AccessConstraints();
    }

}