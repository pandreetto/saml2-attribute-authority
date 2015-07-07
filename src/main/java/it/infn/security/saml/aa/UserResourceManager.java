package it.infn.security.saml.aa;

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

import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.BadRequestException;
import org.wso2.charon.core.exceptions.FormatNotSupportedException;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.protocol.endpoints.UserResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.utils.DefaultCharonManager;
import org.wso2.charon.utils.jaxrs.JAXRSResponseBuilder;

@Path("/Users")
public class UserResourceManager {

    public UserResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Encoder encoder = null;
        SCIMResponse scimResponse = null;
        try {
            DefaultCharonManager defaultCharonManager = DefaultCharonManager.getInstance();
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }
            encoder = defaultCharonManager.getEncoder(SCIMConstants.identifyFormat(format));

            /*
             * TODO user from authentication driver
             */
            UserManager userManager = DefaultCharonManager.getInstance().getUserManager("");
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.get(id, format, userManager);

        } catch (AbstractCharonException ex) {
            scimResponse = AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @POST
    public Response createUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Encoder encoder = null;
        SCIMResponse scimResponse = null;
        try {
            DefaultCharonManager defaultCharonManager = DefaultCharonManager.getInstance();
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new FormatNotSupportedException(error);
            }
            if (outputFormat == null) {
                outputFormat = SCIMConstants.APPLICATION_JSON;
            }
            encoder = defaultCharonManager.getEncoder(SCIMConstants.identifyFormat(outputFormat));

            /*
             * TODO user from authentication driver
             */
            UserManager userManager = DefaultCharonManager.getInstance().getUserManager("");
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.create(resourceString, inputFormat, outputFormat, userManager);

        } catch (AbstractCharonException ex) {
            scimResponse = AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @DELETE
    @Path("{id}")
    public Response deleteUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Encoder encoder = null;
        SCIMResponse scimResponse = null;
        try {
            DefaultCharonManager defaultCharonManager = DefaultCharonManager.getInstance();
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }
            encoder = defaultCharonManager.getEncoder(SCIMConstants.identifyFormat(format));

            /*
             * TODO user from authentication driver
             */
            UserManager userManager = DefaultCharonManager.getInstance().getUserManager("");
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.delete(id, userManager, format);

        } catch (AbstractCharonException ex) {
            scimResponse = AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @GET
    public Response getUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        Encoder encoder = null;
        SCIMResponse scimResponse = null;
        try {
            DefaultCharonManager defaultCharonManager = DefaultCharonManager.getInstance();
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }
            encoder = defaultCharonManager.getEncoder(SCIMConstants.identifyFormat(format));

            /*
             * TODO user from authentication driver
             */
            UserManager userManager = DefaultCharonManager.getInstance().getUserManager("");
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

        } catch (AbstractCharonException ex) {
            scimResponse = AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @PUT
    @Path("{id}")
    public Response updateUser(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Encoder encoder = null;
        SCIMResponse scimResponse = null;
        try {
            DefaultCharonManager defaultCharonManager = DefaultCharonManager.getInstance();
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new FormatNotSupportedException(error);
            }
            if (outputFormat == null) {
                outputFormat = SCIMConstants.APPLICATION_JSON;
            }
            encoder = defaultCharonManager.getEncoder(SCIMConstants.identifyFormat(outputFormat));

            /*
             * TODO user from authentication driver
             */
            UserManager userManager = DefaultCharonManager.getInstance().getUserManager("");
            UserResourceEndpoint userResourceEndpoint = new UserResourceEndpoint();
            scimResponse = userResourceEndpoint.updateWithPUT(id, resourceString, inputFormat, outputFormat,
                    userManager);

        } catch (AbstractCharonException ex) {
            scimResponse = AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

}