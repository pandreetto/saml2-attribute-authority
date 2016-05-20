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
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;

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

@Path("/attributes")
public class AttributeManager {

    public AttributeManager() {

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributeNames(@HeaderParam(SCIMConstants.ACCEPT_HEADER)
    String outputFormat, @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER)
    String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListAttributes(requester);

            DataSource dataSource = DataSourceFactory.getDataSource();
            SchemaManager schemaManager = SchemaManagerFactory.getManager();

            String encodedKeys = schemaManager.encode(dataSource.getAttributeNames(), outputFormat);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedKeys);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @GET
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributeSet(@PathParam("attrName")
    String attrName, @HeaderParam(SCIMConstants.ACCEPT_HEADER)
    String outputFormat, @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER)
    String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowAttribute(requester, attrName);

            DataSource dataSource = DataSourceFactory.getDataSource();
            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrEntry = dataSource.getAttribute(attrName);
            String encodedAttr = schemaManager.encode(attrEntry, outputFormat);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedAttr);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @DELETE
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response deleteAttributeSet(@PathParam("attrName")
    String attrName, @HeaderParam(SCIMConstants.ACCEPT_HEADER)
    String outputFormat, @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER)
    String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteAttribute(requester, attrName);

            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.removeAttribute(attrName);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, null);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @PUT
    @Path("{attrName}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response updateAttributeSet(@PathParam("attrName")
    String attrName, @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER)
    String inputFormat, @HeaderParam(SCIMConstants.ACCEPT_HEADER)
    String outputFormat, @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER)
    String authorization, String payload) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkContentFormat(inputFormat);
            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrItem = schemaManager.parse(payload, inputFormat);
            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.updateAttribute(attrItem);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, payload);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);
        }

        return result;

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response createAttributeSet(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER)
    String inputFormat, @HeaderParam(SCIMConstants.ACCEPT_HEADER)
    String outputFormat, @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER)
    String authorization, String payload) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkContentFormat(inputFormat);
            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SchemaManager schemaManager = SchemaManagerFactory.getManager();
            AttributeEntry attrItem = schemaManager.parse(payload, inputFormat);

            DataSource dataSource = DataSourceFactory.getDataSource();
            dataSource.createAttribute(attrItem);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, payload);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

}