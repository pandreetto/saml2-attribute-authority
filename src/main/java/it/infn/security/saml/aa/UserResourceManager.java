package it.infn.security.saml.aa;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.utils.SCIMUtils;

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
import org.wso2.charon.core.protocol.endpoints.UserResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.utils.jaxrs.JAXRSResponseBuilder;

@Path("/Users")
public class UserResourceManager {

    private static final Logger logger = Logger.getLogger(UserResourceManager.class.getName());

    public UserResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SCIMResponse scimResponse = null;
        try {
            
            format = SCIMUtils.normalizeFormat(format);
            
            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowUser(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource();

            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.get(id, format, userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @POST
    public Response createUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
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
            accessManager.authorizeCreateUser(requester);
            
            DataSource userManager = DataSourceFactory.getDataSource();
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.create(resourceString, inputFormat, outputFormat, userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, outputFormat);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SCIMResponse scimResponse = null;
        try {
            
            format = SCIMUtils.normalizeFormat(format);
            
            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteUser(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource();
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.delete(id, userManager, format);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @GET
    public Response getUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
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
            accessManager.authorizeListUsers(requester);

            DataSource userManager = DataSourceFactory.getDataSource();
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();

            if (searchAttribute != null) {
                scimResponse = userResourceEndpoint.listByAttribute(searchAttribute, userManager, format);
            } else if (filter != null) {
                scimResponse = userResourceEndpoint.listByFilter(filter, userManager, format);
            } else if (startIndex != null && count != null) {
                scimResponse = userResourceEndpoint.listWithPagination(Integer.valueOf(startIndex),
                        Integer.valueOf(count), userManager, format);
            } else if (sortBy != null) {
                scimResponse = userResourceEndpoint.listBySort(sortBy, sortOrder, userManager, format);
            } else if (searchAttribute == null && filter == null && startIndex == null && count == null
                    && sortBy == null) {
                scimResponse = userResourceEndpoint.list(userManager, format);
            } else {
                throw new BadRequestException(ResponseCodeConstants.DESC_BAD_REQUEST_GET);
            }

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, format);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
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
            accessManager.authorizeModifyUser(requester, id);

            DataSource userManager = DataSourceFactory.getDataSource();
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.updateWithPUT(id, resourceString, inputFormat, outputFormat,
                    userManager);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            scimResponse = SCIMUtils.responseFromException(ex, outputFormat);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

}