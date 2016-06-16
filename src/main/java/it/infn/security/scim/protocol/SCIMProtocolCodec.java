package it.infn.security.scim.protocol;

import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.core.SCIMGroup;
import it.infn.security.scim.core.SCIMUser;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.encoder.json.JSONDecoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;
import org.wso2.charon.core.schema.ServerSideValidator;

public class SCIMProtocolCodec {

    private static Logger logger = Logger.getLogger(SCIMProtocolCodec.class.getName());

    private static final String SPID_ATTR_URI = "urn:it:infn:security:saml2:attributes:1.0";

    private static final String SPID_SCHEMA_URI = "urn:it:infn:security:saml2:attributes:1.0";

    private static final String NAME_ATTR_ID = "name";

    private static final String VALUE_ATTR_ID = "value";

    private static final String ROOT_ATTR_ID = "SPIDAttributes";

    private static SCIMResourceSchema groupSchema = null;

    private static SCIMResourceSchema userSchema = null;

    static {

        SCIMSubAttributeSchema nameSchema = SCIMSubAttributeSchema.createSCIMSubAttributeSchema(SPID_ATTR_URI,
                NAME_ATTR_ID, SCIMSchemaDefinitions.DataType.STRING, "Name identifier", false, false, true);

        SCIMSubAttributeSchema contentSchema = SCIMSubAttributeSchema.createSCIMSubAttributeSchema(SPID_ATTR_URI,
                VALUE_ATTR_ID, SCIMSchemaDefinitions.DataType.STRING, "Content identifier", false, false, true);

        SCIMSubAttributeSchema[] subAttributes = new SCIMSubAttributeSchema[] { nameSchema, contentSchema };

        /*
         * TODO move schemaExtension into an OCP package
         */
        SCIMAttributeSchema schemaExtension = SCIMAttributeSchema.createSCIMAttributeSchema(SPID_ATTR_URI,
                ROOT_ATTR_ID, null, true, null, "Short attribute description", SPID_SCHEMA_URI, false, false, false,
                subAttributes);

        if (schemaExtension != null) {

            groupSchema = SCIMResourceSchema.createSCIMResourceSchema(org.wso2.charon.core.schema.SCIMConstants.GROUP,
                    org.wso2.charon.core.schema.SCIMConstants.CORE_SCHEMA_URI,
                    org.wso2.charon.core.schema.SCIMConstants.GROUP_DESC, SCIMConstants.GROUP_ENDPOINT,
                    SCIMSchemaDefinitions.DISPLAY_NAME, SCIMSchemaDefinitions.MEMBERS, schemaExtension);

            userSchema = SCIMResourceSchema.createSCIMResourceSchema(org.wso2.charon.core.schema.SCIMConstants.USER,
                    org.wso2.charon.core.schema.SCIMConstants.CORE_SCHEMA_URI,
                    org.wso2.charon.core.schema.SCIMConstants.USER_DESC, SCIMConstants.USER_ENDPOINT,
                    SCIMSchemaDefinitions.USER_NAME, SCIMSchemaDefinitions.NAME, SCIMSchemaDefinitions.DISPLAY_NAME,
                    SCIMSchemaDefinitions.NICK_NAME, SCIMSchemaDefinitions.PROFILE_URL, SCIMSchemaDefinitions.TITLE,
                    SCIMSchemaDefinitions.USER_TYPE, SCIMSchemaDefinitions.PREFERRED_LANGUAGE,
                    SCIMSchemaDefinitions.LOCALE, SCIMSchemaDefinitions.TIMEZONE, SCIMSchemaDefinitions.ACTIVE,
                    SCIMSchemaDefinitions.PASSWORD, SCIMSchemaDefinitions.EMAILS, SCIMSchemaDefinitions.PHONE_NUMBERS,
                    SCIMSchemaDefinitions.IMS, SCIMSchemaDefinitions.PHOTOS, SCIMSchemaDefinitions.ADDRESSES,
                    SCIMSchemaDefinitions.GROUPS, SCIMSchemaDefinitions.ENTITLEMENTS, SCIMSchemaDefinitions.ROLES,
                    SCIMSchemaDefinitions.X509CERTIFICATES, schemaExtension);
        } else {

            groupSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
            userSchema = SCIMSchemaDefinitions.SCIM_USER_SCHEMA;

        }
    }

    public static String encodeUser(UserResource userRes, boolean validate, boolean removePwd)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        User user = (User) userRes;
        try {

            if (validate) {
                ServerSideValidator.validateRetrievedSCIMObject(user, userSchema);
            }

            if (removePwd) {
                /*
                 * TODO check missing deep copy
                 */
                ServerSideValidator.removePasswordOnReturn(user);
            }

            return encoder.encodeSCIMObject(user);

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static UserResource decodeUser(String usrStr, boolean validate)
        throws SchemaManagerException {
        JSONDecoder decoder = new JSONDecoder();
        try {

            SCIMUser user = (SCIMUser) decoder.decodeResource(usrStr, userSchema, new SCIMUser());
            if (validate) {
                ServerSideValidator.validateCreatedSCIMObject(user, userSchema);
            }
            return user;

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static UserResource checkUserUpdate(UserResource oldUsr, UserResource newUsr)
        throws SchemaManagerException {
        try {
            return (UserResource) ServerSideValidator.validateUpdatedSCIMObject((User) oldUsr, (User) newUsr,
                    userSchema);
        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static final String encodeUserSearchResult(UserSearchResult searchResult)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        try {
            ListedResource listedResource = new ListedResource();
            if (searchResult == null || searchResult.isEmpty()) {
                listedResource.setTotalResults(0);
            } else {
                listedResource.setTotalResults(searchResult.getTotalResults());
                for (UserResource user : searchResult.getUserList()) {
                    Map<String, Attribute> userAttributes = ((User) user).getAttributeList();
                    listedResource.setResources(userAttributes);
                }
            }
            return encoder.encodeSCIMObject(listedResource);
        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static String encodeGroup(GroupResource groupRes, boolean validate)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        Group group = (Group) groupRes;
        try {

            if (validate) {
                ServerSideValidator.validateRetrievedSCIMObject(group, groupSchema);
            }
            return encoder.encodeSCIMObject(group);

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static GroupResource decodeGroup(String grpStr, boolean validate)
        throws SchemaManagerException {

        JSONDecoder decoder = new JSONDecoder();
        try {

            SCIMGroup group = (SCIMGroup) decoder.decodeResource(grpStr, groupSchema, new SCIMGroup());
            if (validate) {
                ServerSideValidator.validateCreatedSCIMObject(group, groupSchema);
            }
            return group;

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static GroupResource checkGroupUpdate(GroupResource oldGrp, GroupResource newGrp)
        throws SchemaManagerException {
        try {
            return (GroupResource) ServerSideValidator.validateUpdatedSCIMObject((Group) oldGrp, (Group) newGrp,
                    groupSchema);
        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static String encodeGroupSearchResult(GroupSearchResult searchResult)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        try {
            ListedResource listedResource = new ListedResource();
            if (searchResult == null || searchResult.isEmpty()) {
                listedResource.setTotalResults(0);
            } else {
                listedResource.setTotalResults(searchResult.getTotalResults());
                for (GroupResource group : searchResult.getGroupList()) {
                    if (group != null) {
                        Map<String, Attribute> attributesOfGroupResource = ((Group) group).getAttributeList();
                        listedResource.setResources(attributesOfGroupResource);
                    }
                }
            }
            return encoder.encodeSCIMObject(listedResource);
        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static Response responseFromException(Exception ex) {
        AbstractCharonException chEx = null;

        logger.log(Level.INFO, "Detected exception " + ex.getMessage(), ex);

        if (ex instanceof AbstractCharonException) {

            chEx = (AbstractCharonException) ex;
            if (chEx.getCode() == -1) {
                chEx.setCode(SCIMConstants.CODE_INTERNAL_SERVER_ERROR);
            }

        } else if (ex instanceof CodedException) {

            int code = ((CodedException) ex).getCode();
            if (code >= 600) {
                code = 500;
            }
            chEx = new AbstractCharonException(code, ex.getMessage());

        } else {

            int code = 500;
            String msg = "Internal server error: " + ex.getMessage();
            chEx = new AbstractCharonException(code, msg);

        }

        Encoder encoder = new JSONEncoder();
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
        return buildResponse(chEx.getCode(), httpHeaders, encoder.encodeSCIMException(chEx));
    }

    public static Response buildResponse(int code, Map<String, String> httpHeaders, String message) {

        Response.ResponseBuilder responseBuilder = Response.status(code);

        if (httpHeaders != null && httpHeaders.size() != 0) {
            for (Map.Entry<String, String> entry : httpHeaders.entrySet()) {
                responseBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        if (message != null) {
            responseBuilder.entity(message);
        }

        return responseBuilder.build();
    }

    public static void checkAcceptedFormat(String format)
        throws SchemaManagerException {
        if (format == null || format.equals("*/*"))
            return;
        if (!format.contains(SCIMConstants.APPLICATION_JSON)) {
            logger.severe("Wrong accepted format: " + format);
            throw new SchemaManagerException("Unsupported accepted format " + format);
        }
    }

    public static void checkContentFormat(String format)
        throws SchemaManagerException {
        if (format == null)
            throw new SchemaManagerException("Missing content type format");
        if (!format.contains(SCIMConstants.APPLICATION_JSON)) {
            logger.severe("Wrong content type format: " + format);
            throw new SchemaManagerException("Unsupported content type format " + format);
        }
    }

}