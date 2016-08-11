package it.infn.security.saml.iam.impl;

import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

public class LDAPAccessManager
    extends SimpleAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(LDAPAccessManager.class.getName());

    private static final String LDAP_URL_PARAM = "authorization.ldap.url";

    private static final String LDAP_AUTH_TYPE = "authorization.ldap.auth.type";

    private static final String LDAP_AUTH_USER = "authorization.ldap.auth.user";

    private static final String LDAP_AUTH_CRED = "authorization.ldap.auth.credential";

    private Hashtable<String, Object> configTable;

    public void init()
        throws AccessManagerException {
        super.init();

        try {

            AuthorityConfiguration authConf = AuthorityConfigurationFactory.getConfiguration();

            configTable.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            configTable.put(Context.PROVIDER_URL, authConf.getAccessManagerParam(LDAP_URL_PARAM));

            String authType = authConf.getAccessManagerParam(LDAP_AUTH_TYPE, "none").toLowerCase();
            configTable.put(Context.SECURITY_AUTHENTICATION, authType);
            if (!authType.equals("none")) {
                configTable.put(Context.SECURITY_PRINCIPAL, authConf.getAccessManagerParam(LDAP_AUTH_USER));
                configTable.put(Context.SECURITY_CREDENTIALS, authConf.getAccessManagerParam(LDAP_AUTH_CRED));
            }
            configTable.put("com.sun.jndi.ldap.connect.pool", "true");

        } catch (Throwable th) {
            throw new AccessManagerException(th.getMessage());
        }
    }

    private boolean isAdmin(Subject requester)
        throws AccessManagerException {

        DirContext ctx = null;
        try {

            ctx = new InitialDirContext(configTable);
            for (X500Principal user : requester.getPrincipals(X500Principal.class)) {

                try {

                    Object result = ctx.lookup(user.getName());
                    logger.fine("Found class " + result.getClass().getCanonicalName());
                    return true;

                } catch (NameNotFoundException nfEx) {
                    logger.info("User not recognized " + user.getName());
                }

            }

        } catch (Exception ex) {

            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new AccessManagerException("Cannot contact ldap server");

        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
            }
        }

        return false;
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeCreateAttribute(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeModifyAttribute(Subject requester, String attrId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeDeleteAttribute(Subject requester, String attrId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeShowAttribute(Subject requester, String attrId)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public AccessConstraints authorizeListAttributes(Subject requester)
        throws AccessManagerException {

        if (isAdmin(requester))
            return new AccessConstraints();

        throw new AccessManagerException("Operation not allowed", AccessManagerException.UNAUTHORIZED);

    }

    public void close()
        throws AccessManagerException {
        super.close();
    }

    public int getLoadPriority() {
        return super.getLoadPriority() + 1;
    }

}