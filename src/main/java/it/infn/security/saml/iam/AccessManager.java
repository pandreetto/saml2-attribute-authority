package it.infn.security.saml.iam;

import java.util.ServiceLoader;

import javax.security.auth.Subject;

public interface AccessManager {

    public void init()
        throws AccessManagerException;

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQueryParameters queryParams)
        throws AccessManagerException;

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException;

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException;

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException;

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException;

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException;

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException;

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException;

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException;

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException;

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException;

    public AccessConstraints authorizeCreateAttribute(Subject requester)
        throws AccessManagerException;

    public AccessConstraints authorizeModifyAttribute(Subject requester, String attrId)
        throws AccessManagerException;

    public AccessConstraints authorizeDeleteAttribute(Subject requester, String attrId)
        throws AccessManagerException;

    public AccessConstraints authorizeShowAttribute(Subject requester, String attrId)
        throws AccessManagerException;

    public AccessConstraints authorizeListAttributes(Subject requester)
        throws AccessManagerException;

    public void close()
        throws AccessManagerException;

    public int getLoadPriority();

    public static ServiceLoader<AccessManager> accessManagerLoader = ServiceLoader.load(AccessManager.class);

}