package it.infn.security.saml.aa;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.utils.SCIMUtils;
import it.infn.security.saml.utils.charon.GroupResourceEndpoint;
import it.infn.security.saml.utils.charon.JAXRSResponseBuilder;

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
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.wso2.charon.core.exceptions.BadRequestException;
import org.wso2.charon.core.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.schema.SCIMConstants;

@Path("/Groups")
public class GroupResourceManager {

    private static final Logger logger = Logger.getLogger(GroupResourceManager.class.getName());

    public GroupResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SCIMResponse scimResponse = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowGroup(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.get(id, format, userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return JAXRSResponseBuilder.buildResponse(scimResponse);

    }

    @POST
    public Response createGroup(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        SCIMResponse scimResponse = null;
        try {

            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new FormatNotSupportedException(error);
            }
            inputFormat = SCIMUtils.normalizeFormat(inputFormat);
            outputFormat = SCIMUtils.normalizeFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateGroup(requester);

            DataSource userManager = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.create(resourceString, inputFormat, outputFormat, userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, outputFormat);
        }

        return JAXRSResponseBuilder.buildResponse(scimResponse);

    }

    @DELETE
    @Path("{id}")
    public Response deleteGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SCIMResponse scimResponse = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteGroup(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.delete(id, userManager, format);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return JAXRSResponseBuilder.buildResponse(scimResponse);

    }

    @GET
    public Response getGroup(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        SCIMResponse scimResponse = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListGroups(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();

            if (searchAttribute != null) {
                throw new BadRequestException(ResponseCodeConstants.DESC_BAD_REQUEST_GET);
            } else {
                int sIdx = (startIndex != null) ? Integer.parseInt(startIndex) : -1;
                int cnt = (count != null) ? Integer.parseInt(count) : -1;
                scimResponse = groupResourceEndpoint.listByParams(filter, sortBy, sortOrder, sIdx, cnt, dataSource,
                        format);
            }

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return JAXRSResponseBuilder.buildResponse(scimResponse);

    }

    @PUT
    @Path("{id}")
    public Response updateGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        SCIMResponse scimResponse = null;
        try {
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new FormatNotSupportedException(error);
            }

            inputFormat = SCIMUtils.normalizeFormat(inputFormat);
            outputFormat = SCIMUtils.normalizeFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeModifyGroup(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.updateWithPUT(id, resourceString, inputFormat, outputFormat,
                    userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, outputFormat);
        }

        return JAXRSResponseBuilder.buildResponse(scimResponse);

    }

}