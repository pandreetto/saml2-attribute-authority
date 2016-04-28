package it.infn.security.saml.iam.impl;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessConstraints;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerException;
import it.infn.security.saml.iam.AttributeQueryParameters;
import it.infn.security.saml.iam.EntityIdPrincipal;
import it.infn.security.saml.schema.AttributeNameInterface;
import it.infn.security.saml.spmetadata.MetadataSource;
import it.infn.security.saml.spmetadata.MetadataSourceFactory;

import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

public class SimpleAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(SimpleAccessManager.class.getName());

    public static final String ONLY_SP_MODE = "authorization.mode.onlysp";

    private boolean onlySPMode;

    public void init()
        throws AccessManagerException {

        try {

            AuthorityConfiguration authConf = AuthorityConfigurationFactory.getConfiguration();
            String tmps = authConf.getAccessManagerParam(ONLY_SP_MODE, "true");
            onlySPMode = tmps.equalsIgnoreCase("true");

        } catch (Throwable th) {
            throw new AccessManagerException(th.getMessage());
        }
    }

    public AccessConstraints authorizeAttributeQuery(Subject subject, AttributeQueryParameters queryParams)
        throws AccessManagerException {

        AccessConstraints result = new AccessConstraints();

        if (onlySPMode) {

            Set<EntityIdPrincipal> tmpset = subject.getPrincipals(EntityIdPrincipal.class);
            String errStr = null;

            if (tmpset != null && tmpset.size() > 0) {
                try {

                    EntityIdPrincipal entityId = tmpset.iterator().next();

                    MetadataSource mdSource = MetadataSourceFactory.getMetadataSource();
                    DataSource dataSource = DataSourceFactory.getDataSource();

                    Set<String> spRequiredAttrs = mdSource.getMetadata(entityId.getName()).getAttributeSet();
                    for (AttributeNameInterface name : dataSource.getAttributeNames()) {
                        String attName = name.getNameId();
                        if (spRequiredAttrs.contains(attName)) {
                            result.addAttribute(attName);
                        }
                    }

                    if (result.getAttributes().size() > 0)
                        return result;

                    errStr = "No attribute matching for query " + queryParams.getId();

                } catch (Throwable th) {
                    logger.log(Level.SEVERE, th.getMessage(), th);
                }
            }

            if (errStr != null)
                errStr = "Authorization denied for query " + queryParams.getId();
            throw new AccessManagerException(errStr);
        }

        return result;
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