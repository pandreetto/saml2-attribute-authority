package it.infn.security.scim.protocol;

import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.core.SCIM2Decoder;
import it.infn.security.scim.core.SCIM2Encoder;
import it.infn.security.scim.core.SCIM2Group;
import it.infn.security.scim.core.SCIM2User;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

public class SCIMProtocolCodec {

    private static Logger logger = Logger.getLogger(SCIMProtocolCodec.class.getName());

    private static String servicePrefix = null;

    private static String getServicePrefix() {

        if (servicePrefix == null) {
            synchronized (SCIMProtocolCodec.class) {
                if (servicePrefix == null) {
                    try {
                        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
                        servicePrefix = configuration.getAuthorityURL() + "/manager";
                    } catch (Exception ex) {
                        logger.log(Level.SEVERE, ex.getMessage(), ex);
                    }
                }
            }
        }
        return servicePrefix;
    }

    public static String encodeUser(UserResource userRes)
        throws SchemaManagerException {

        try {

            SCIM2User result = (SCIM2User) userRes;
            result.setUserPwd(null);
            return SCIM2Encoder.encodeUser(result, getServicePrefix());

        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }

    }

    public static UserResource decodeUser(String usrStr)
        throws SchemaManagerException {

        try {
            return SCIM2Decoder.decodeUser(usrStr);
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }

    }

    public static UserResource checkUserUpdate(UserResource oldUsr, UserResource newUsr)
        throws SchemaManagerException {

        try {

            newUsr.setResourceId(oldUsr.getResourceId());
            newUsr.setResourceCreationDate(oldUsr.getResourceCreationDate());
            newUsr.setResourceChangeDate(new Date());
            newUsr.setResourceVersion(oldUsr.getResourceVersion());
            return newUsr;
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }
    }

    public static final String encodeUserSearchResult(UserSearchResult searchResult)
        throws SchemaManagerException {

        try {
            return SCIM2Encoder.encodeUserList(searchResult, getServicePrefix());
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }

    }

    public static String encodeGroup(GroupResource groupRes)
        throws SchemaManagerException {

        try {
            return SCIM2Encoder.encodeGroup((SCIM2Group) groupRes, getServicePrefix());
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }

    }

    public static GroupResource decodeGroup(String grpStr)
        throws SchemaManagerException {

        try {
            return SCIM2Decoder.decodeGroup(grpStr);
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }
    }

    public static GroupResource checkGroupUpdate(GroupResource oldGrp, GroupResource newGrp)
        throws SchemaManagerException {

        try {

            newGrp.setResourceId(oldGrp.getResourceId());
            newGrp.setResourceCreationDate(oldGrp.getResourceCreationDate());
            newGrp.setResourceChangeDate(new Date());
            newGrp.setResourceVersion(oldGrp.getResourceVersion());
            return newGrp;
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }
    }

    public static String encodeGroupSearchResult(GroupSearchResult searchResult)
        throws SchemaManagerException {

        try {
            return SCIM2Encoder.encodeGroupList(searchResult, getServicePrefix());
        } catch (DataSourceException dsEx) {
            throw new SchemaManagerException(dsEx.getMessage(), dsEx);
        }

    }

    public static Response responseFromException(Exception ex) {

        logger.log(Level.INFO, "Detected exception " + ex.getMessage(), ex);

        int code = SCIMConstants.CODE_INTERNAL_SERVER_ERROR;
        String message = null;

        if (ex instanceof CodedException) {
            CodedException cEx = (CodedException) ex;
            code = cEx.getCode();
            message = cEx.getMessage();
        } else {
            message = "Internal server error";
        }

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
        return buildResponse(code, httpHeaders, SCIM2Encoder.encodeException(code, message));
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