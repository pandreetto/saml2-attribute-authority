package it.infn.security.saml.iam;

import java.util.ServiceLoader;

import javax.security.auth.Subject;

import org.opensaml.saml2.core.AttributeQuery;

public interface AccessManager {

    public void init()
        throws AccessManagerException;

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQuery query)
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

    public void close()
        throws AccessManagerException;

    public int getLoadPriority();

    public static ServiceLoader<AccessManager> accessManagerLoader = ServiceLoader.load(AccessManager.class);

}