package it.infn.security.saml.aa;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.utils.SCIMUtils;
import it.infn.security.saml.utils.charon.GroupResourceEndpoint;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

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
import javax.ws.rs.core.Response;

@Path(SCIMConstants.GROUP_ENDPOINT)
public class GroupResourceManager {

    private static final Logger logger = Logger.getLogger(GroupResourceManager.class.getName());

    public GroupResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getGroup(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            result = groupResourceEndpoint.get(id, format, dataSource);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response createGroup(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Response result = null;
        try {

            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new CodedException(error);
            }
            inputFormat = SCIMUtils.normalizeFormat(inputFormat);
            outputFormat = SCIMUtils.normalizeFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateGroup(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            result = groupResourceEndpoint.create(resourceString, inputFormat, outputFormat, dataSource);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @DELETE
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response deleteGroup(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            result = groupResourceEndpoint.delete(id, dataSource, format);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getGroup(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        Response result = null;
        try {

            format = SCIMUtils.normalizeFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListGroups(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();

            if (searchAttribute != null) {
                throw new CodedException(SCIMConstants.DESC_BAD_REQUEST_GET);
            } else {
                int sIdx = (startIndex != null) ? Integer.parseInt(startIndex) : -1;
                int cnt = (count != null) ? Integer.parseInt(count) : -1;
                result = groupResourceEndpoint.listByParams(filter, sortBy, sortOrder, sIdx, cnt, dataSource, format);
            }

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @PUT
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response updateGroup(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Response result = null;
        try {
            if (inputFormat == null) {
                String error = SCIMConstants.CONTENT_TYPE_HEADER + " not present in the request header.";
                throw new CodedException(error);
            }

            inputFormat = SCIMUtils.normalizeFormat(inputFormat);
            outputFormat = SCIMUtils.normalizeFormat(outputFormat);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeModifyGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            GroupResourceEndpoint groupResourceEndpoint = new GroupResourceEndpoint();
            result = groupResourceEndpoint.updateWithPUT(id, resourceString, inputFormat, outputFormat, dataSource);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

}