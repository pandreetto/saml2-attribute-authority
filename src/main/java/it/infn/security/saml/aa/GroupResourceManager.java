package it.infn.security.saml.aa;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;

import java.util.logging.Logger;

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
import org.wso2.charon.core.protocol.endpoints.GroupResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.utils.jaxrs.JAXRSResponseBuilder;

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
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }

            DataSource userManager = DataSourceFactory.getDataSource();
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.get(id, format, userManager);

        } catch (Exception ex) {
            /*
             * TODO exception handling
             */
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

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
            if (outputFormat == null) {
                outputFormat = SCIMConstants.APPLICATION_JSON;
            }

            DataSource userManager = DataSourceFactory.getDataSource();
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.create(resourceString, inputFormat, outputFormat, userManager);

        } catch (Exception ex) {
            /*
             * TODO exception handling
             */
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @DELETE
    @Path("{id}")
    public Response deleteGroup(@PathParam(SCIMConstants.CommonSchemaConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SCIMResponse scimResponse = null;
        try {
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }

            DataSource userManager = DataSourceFactory.getDataSource();
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.delete(id, userManager, format);

        } catch (Exception ex) {
            /*
             * TODO exception handling
             */
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

    @GET
    public Response getGroup(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        SCIMResponse scimResponse = null;
        try {
            if (format == null) {
                format = SCIMConstants.APPLICATION_JSON;
            }

            logger.info("Calling getGroup, format " + SCIMConstants.identifyFormat(format));

            DataSource userManager = DataSourceFactory.getDataSource();
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();

            if (searchAttribute != null) {
                scimResponse = groupResourceEndpoint.listByAttribute(searchAttribute, userManager, format);
            } else if (filter != null) {
                scimResponse = groupResourceEndpoint.listByFilter(filter, userManager, format);
            } else if (startIndex != null && count != null) {
                scimResponse = groupResourceEndpoint.listWithPagination(Integer.valueOf(startIndex),
                        Integer.valueOf(count), userManager, format);
            } else if (sortBy != null) {
                scimResponse = groupResourceEndpoint.listBySort(sortBy, sortOrder, userManager, format);
            } else if (searchAttribute == null && filter == null && startIndex == null && count == null
                    && sortBy == null) {
                scimResponse = groupResourceEndpoint.list(userManager, format);
            } else {
                throw new BadRequestException(ResponseCodeConstants.DESC_BAD_REQUEST_GET);
            }

        } catch (Exception ex) {
            /*
             * TODO exception handling
             */
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

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
            if (outputFormat == null) {
                outputFormat = SCIMConstants.APPLICATION_JSON;
            }

            DataSource userManager = DataSourceFactory.getDataSource();
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            scimResponse = groupResourceEndpoint.updateWithPUT(id, resourceString, inputFormat, outputFormat,
                    userManager);

        } catch (Exception ex) {
            /*
             * TODO exception handling
             */
        }

        return new JAXRSResponseBuilder().buildResponse(scimResponse);

    }

}