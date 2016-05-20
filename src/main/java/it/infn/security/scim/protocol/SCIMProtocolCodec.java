package it.infn.security.scim.protocol;

import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.iam.AccessManagerException;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;
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
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.ServerSideValidator;

public class SCIMProtocolCodec {

    private static Logger logger = Logger.getLogger(SCIMProtocolCodec.class.getName());

    public static String encodeUser(UserResource userRes, boolean validate, boolean removePwd)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        User user = (User) userRes;
        try {

            if (validate) {
                SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
                ServerSideValidator.validateRetrievedSCIMObject(user, schema);
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

            SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
            SCIMUser user = (SCIMUser) decoder.decodeResource(usrStr, schema, new SCIMUser());
            if (validate) {
                ServerSideValidator.validateCreatedSCIMObject(user, schema);
            }
            return user;

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static UserResource checkUserUpdate(UserResource oldUsr, UserResource newUsr)
        throws SchemaManagerException {
        SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
        try {
            /*
             * TODO check cast
             */
            return (UserResource) ServerSideValidator.validateUpdatedSCIMObject((User) oldUsr, (User) newUsr, schema);
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
                SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
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

            SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
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
        SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
        try {
            /*
             * TODO check cast
             */
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

        logger.log(Level.FINE, "Detected exception " + ex.getMessage(), ex);

        if (ex instanceof AbstractCharonException) {

            chEx = (AbstractCharonException) ex;
            if (chEx.getCode() == -1) {
                chEx.setCode(SCIMConstants.CODE_INTERNAL_SERVER_ERROR);
            }

        } else if (ex instanceof AccessManagerException) {

            int code = 401;
            String msg = "Authorization failure";
            chEx = new AbstractCharonException(code, msg);

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
        if (format == null)
            return;
        if (!format.equals(SCIMConstants.APPLICATION_JSON))
            throw new SchemaManagerException("Unsupported accepted format " + format);
    }

    public static void checkContentFormat(String format)
        throws SchemaManagerException {
        if (format == null)
            throw new SchemaManagerException("Missing content type format");
        if (!format.equals(SCIMConstants.APPLICATION_JSON))
            throw new SchemaManagerException("Unsupported content type format " + format);
    }

}