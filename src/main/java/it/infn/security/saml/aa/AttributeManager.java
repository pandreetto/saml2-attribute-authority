package it.infn.security.saml.aa;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerFactory;
import it.infn.security.saml.utils.SCIMUtils;
import it.infn.security.saml.utils.charon.JAXRSResponseBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.schema.SCIMConstants;

@Path("/attributes")
public class AttributeManager {

    private static final Logger logger = Logger.getLogger(AttributeManager.class.getName());

    public AttributeManager() {

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributeNames(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListAttributes(requester);

            DataSource dataSource = DataSourceFactory.getDataSource();
            SchemaManager schemaManager = SchemaManagerFactory.getManager();

            String encodedKeys = schemaManager.encode(dataSource.getAttributeNames(), outputFormat);
            return buildResponse(encodedKeys, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @GET
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributeSet(@PathParam("attrName") String attrName,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowAttribute(requester, attrName);

            DataSource dataSource = DataSourceFactory.getDataSource();
            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrEntry = dataSource.getAttribute(attrName);
            String encodedAttr = schemaManager.encode(attrEntry, outputFormat);
            return buildResponse(encodedAttr, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @DELETE
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response deleteAttributeSet(@PathParam("attrName") String attrName,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteAttribute(requester, attrName);

            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.removeAttribute(attrName);
            return buildResponse(ResponseCodeConstants.CODE_OK, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @PUT
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response updateAttributeSet(@PathParam("attrName") String attrName,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String payload) {

        inputFormat = SCIMUtils.normalizeFormat(inputFormat);
        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(inputFormat))
                || !SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrItem = schemaManager.parse(payload, inputFormat);
            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.updateAttribute(attrItem);
            return buildResponse(payload, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response createAttributeSet(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String payload) {

        inputFormat = SCIMUtils.normalizeFormat(inputFormat);
        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(inputFormat))
                || !SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrItem = schemaManager.parse(payload, inputFormat);

            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.createAttribute(attrItem);
            return buildResponse(payload, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    private Response buildResponse(String message, String format) {

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return JAXRSResponseBuilder.buildResponse(ResponseCodeConstants.CODE_OK, httpHeaders, message);

    }

    private Response buildResponse(int code, String format) {
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return JAXRSResponseBuilder.buildResponse(code, httpHeaders, null);
    }

}