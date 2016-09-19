package it.infn.security.saml.aa;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;
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

@Path(SCIMConstants.USER_ENDPOINT)
public class UserResourceManager {

    private static final Logger logger = Logger.getLogger(UserResourceManager.class.getName());

    public UserResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getUser(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowUser(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource user = dataSource.getUser(id);

            String encodedUser = SCIMProtocolCodec.encodeUser(user);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response createUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkContentFormat(inputFormat);
            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateUser(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource user = SCIMProtocolCodec.decodeUser(resourceString);

            UserResource createdUser = dataSource.createUser(user);

            String encodedUser = SCIMProtocolCodec.encodeUser(createdUser);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = configuration.getAuthorityURL() + "/manager" + SCIMConstants.USER_ENDPOINT + "/"
                    + createdUser.getResourceId();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedUser);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @DELETE
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response deleteUser(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteUser(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);
            dataSource.deleteUser(id);

            return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_NO_CONTENT, null, null);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListUsers(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            if (searchAttribute != null) {
                logger.fine("Unsupported query with attributes");
                throw new CodedException(SCIMConstants.DESC_BAD_REQUEST_GET);
            } else {
                int sIdx = (startIndex != null) ? Integer.parseInt(startIndex) : -1;
                int cnt = (count != null) ? Integer.parseInt(count) : -1;

                UserSearchResult searchResult = dataSource.listUsers(filter, sortBy, sortOrder, sIdx, cnt);

                String encodedListedResource = SCIMProtocolCodec.encodeUserSearchResult(searchResult);

                Map<String, String> httpHeaders = new HashMap<String, String>();
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);
                result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

            }

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @PUT
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response updateUser(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkContentFormat(inputFormat);
            SCIMProtocolCodec.checkAcceptedFormat(outputFormat);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeModifyUser(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource oldUser = dataSource.getUser(id);
            UserResource newUser = SCIMProtocolCodec.decodeUser(resourceString);

            UserResource validatedUser = SCIMProtocolCodec.checkUserUpdate(oldUser, newUser);

            UserResource updatedUser = dataSource.updateUser(validatedUser);

            String encodedUser = SCIMProtocolCodec.encodeUser(updatedUser);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = configuration.getAuthorityURL() + "/manager" + SCIMConstants.USER_ENDPOINT + "/"
                    + updatedUser.getResourceId();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

}