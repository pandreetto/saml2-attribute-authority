package it.infn.security.scim.protocol;

import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.iam.AccessManagerException;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;

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

    public static String encodeUser(User user, boolean validate, boolean removePwd)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
        try {

            if (validate) {
                SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
                ServerSideValidator.validateRetrievedSCIMObject(user, schema);
            }

            if (removePwd) {
                ServerSideValidator.removePasswordOnReturn(user);
            }

            return encoder.encodeSCIMObject(user);

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static User decodeUser(String usrStr, boolean validate)
        throws SchemaManagerException {
        JSONDecoder decoder = new JSONDecoder();
        try {

            SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
            User user = (User) decoder.decodeResource(usrStr, schema, new User());
            if (validate) {
                ServerSideValidator.validateCreatedSCIMObject(user, schema);
            }
            return user;

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static User checkUserUpdate(User oldUsr, User newUsr)
        throws SchemaManagerException {
        SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
        try {
            return (User) ServerSideValidator.validateUpdatedSCIMObject(oldUsr, newUsr, schema);
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
                for (User user : searchResult.getUserList()) {
                    Map<String, Attribute> userAttributes = user.getAttributeList();
                    listedResource.setResources(userAttributes);
                }
            }
            return encoder.encodeSCIMObject(listedResource);
        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static String encodeGroup(Group group, boolean validate)
        throws SchemaManagerException {

        JSONEncoder encoder = new JSONEncoder();
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

    public static Group decodeGroup(String grpStr, boolean validate)
        throws SchemaManagerException {

        JSONDecoder decoder = new JSONDecoder();
        try {

            SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
            Group group = (Group) decoder.decodeResource(grpStr, groupSchema, new Group());
            if (validate) {
                ServerSideValidator.validateCreatedSCIMObject(group, groupSchema);
            }
            return group;

        } catch (AbstractCharonException chEx) {
            throw new SchemaManagerException(chEx.getMessage(), chEx);
        }
    }

    public static Group checkGroupUpdate(Group oldGrp, Group newGrp)
        throws SchemaManagerException {
        SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
        try {
            return (Group) ServerSideValidator.validateUpdatedSCIMObject(oldGrp, newGrp, groupSchema);
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
                for (Group group : searchResult.getGroupList()) {
                    if (group != null) {
                        Map<String, Attribute> attributesOfGroupResource = group.getAttributeList();
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

}