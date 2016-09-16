package it.infn.security.saml.iam.impl;

import java.io.File;
import java.io.FileReader;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
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

public class SimpleAccessManager
    implements AccessManager {

    private static final Logger logger = Logger.getLogger(SimpleAccessManager.class.getName());

    public static final String ONLY_SP_MODE = "authorization.mode.onlysp";

    public static final String ACL_FILENAME = "authorization.acl.filename";

    public static final String QUIET_TIME = "authorization.refresh.quite.time";

    public static final String DEFAULT_ACL_FILE = "/etc/saml2-attribute-authority/acl.json";

    public static final String ADMIN_PROPERTY = "administrators";

    public static final String BAN_PROPERTY = "banned_users";

    private boolean onlySPMode;

    private File aclFile;

    private long lastModACL;

    private long tick;

    private long quiteTime;

    private HashSet<String> adminTable;

    private HashSet<String> banTable;

    public void init()
        throws AccessManagerException {

        adminTable = new HashSet<String>();
        banTable = new HashSet<String>();
        lastModACL = 0;
        tick = System.currentTimeMillis();

        try {

            AuthorityConfiguration authConf = AuthorityConfigurationFactory.getConfiguration();
            onlySPMode = authConf.getAccessManagerParam(ONLY_SP_MODE, "false").equalsIgnoreCase("true");

            aclFile = new File(authConf.getAccessManagerParam(ACL_FILENAME, DEFAULT_ACL_FILE));
            quiteTime = authConf.getAccessManagerParamAsInt(QUIET_TIME, 5000);

        } catch (ConfigurationException cEx) {

            throw new AccessManagerException(cEx.getMessage(), cEx.getCode());

        }

        loadACL();

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
                    logger.fine("Calculating access for " + entityId.getName());

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

            if (errStr == null)
                errStr = "Authorization denied for query " + queryParams.getId();
            throw new AccessManagerException(errStr, AccessManagerException.UNAUTHORIZED);
        }

        return result;
    }

    public AccessConstraints authorizeCreateUser(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeModifyUser(Subject requester, String userId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeDeleteUser(Subject requester, String userId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeShowUser(Subject requester, String userId)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public AccessConstraints authorizeListUsers(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public AccessConstraints authorizeCreateGroup(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeModifyGroup(Subject requester, String groupId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeDeleteGroup(Subject requester, String groupId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeShowGroup(Subject requester, String groupId)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public AccessConstraints authorizeListGroups(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public AccessConstraints authorizeCreateAttribute(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeModifyAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeDeleteAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        checkSubject(requester, true);
        return null;
    }

    public AccessConstraints authorizeShowAttribute(Subject requester, String attrId)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public AccessConstraints authorizeListAttributes(Subject requester)
        throws AccessManagerException {
        checkSubject(requester, false);
        return null;
    }

    public void close()
        throws AccessManagerException {

    }

    public int getLoadPriority() {
        return 1;
    }

    private void loadACL()
        throws AccessManagerException {

        JsonReader jReader = null;
        adminTable.clear();
        banTable.clear();

        try {
            if (!aclFile.canRead()) {
                logger.warning("Cannot read " + aclFile.getAbsolutePath() + "; disabled administration");
                return;
            }

            jReader = Json.createReader(new FileReader(aclFile));
            JsonObject rootObj = jReader.readObject();

            JsonArray tmpArray = rootObj.getJsonArray(ADMIN_PROPERTY);
            if (tmpArray != null) {
                for (JsonValue jValue : tmpArray) {
                    adminTable.add(((JsonString) jValue).getString());
                }
            }

            tmpArray = rootObj.getJsonArray(BAN_PROPERTY);
            if (tmpArray != null) {
                for (JsonValue jValue : tmpArray) {
                    banTable.add(((JsonString) jValue).getString());
                }
            }

        } catch (Exception ex) {

            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new AccessManagerException("Cannot configure authorization", 500);

        } finally {
            if (jReader != null)
                try {
                    jReader.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
        }

    }

    private void checkSubject(Subject requester, boolean chkAdmin)
        throws AccessManagerException {
        boolean found = false;

        long now = System.currentTimeMillis();
        if ((now - tick) > quiteTime) {
            if (aclFile.lastModified() != lastModACL) {
                synchronized (SimpleAccessManager.class) {
                    if (aclFile.lastModified() != lastModACL) {
                        tick = now;
                        loadACL();
                        lastModACL = aclFile.lastModified();
                        logger.info("Reloaded ACL file: " + aclFile.getAbsolutePath());
                    }
                }
            }
        }

        for (X500Principal tmpp : requester.getPrincipals(X500Principal.class)) {
            if ((chkAdmin && adminTable.contains(tmpp.getName())) || (!chkAdmin && banTable.contains(tmpp.getName()))) {
                found = true;
                break;
            }
        }

        if (found && !chkAdmin) {
            throw new AccessManagerException("User banned", AccessManagerException.FORBIDDEN);
        }

        if (!found && chkAdmin) {
            throw new AccessManagerException("User is not administrator", AccessManagerException.FORBIDDEN);
        }
    }

}