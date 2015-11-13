package it.infn.security.saml.iam.impl;

import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;
import it.infn.security.saml.iam.AttributeQueryParameters;

import javax.security.auth.Subject;

public class SimpleAccessManager
    implements AccessManager {

    public void init()
        throws AccessManagerException {

    }

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQueryParameters queryParams)
        throws AccessManagerException {
        return new AccessConstraints();
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeCreateAttribute(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeModifyAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeDeleteAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeShowAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        return null;
    }

    public AccessConstraints authorizeListAttributes(Subject requester)
        throws AccessManagerException {
        return null;
    }

    public void close()
        throws AccessManagerException {

    }

    public int getLoadPriority() {
        return 1;
    }

}