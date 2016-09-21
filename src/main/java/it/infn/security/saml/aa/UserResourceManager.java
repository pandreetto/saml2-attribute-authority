package it.infn.security.saml.aa;

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
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.core.AttributeFilter;
import it.infn.security.scim.core.SCIM2Decoder;
import it.infn.security.scim.core.SCIM2Encoder;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

@Path(SCIMConstants.USER_ENDPOINT)
public class UserResourceManager {

    @SuppressWarnings("unused")
    private static final Logger logger = Logger.getLogger(UserResourceManager.class.getName());

    public UserResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getUser(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format, @QueryParam("attributes") String reqAttributes,
            @QueryParam("excludedAttributes") String exclAttributes,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowUser(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource user = dataSource.getUser(id);

            AttributeFilter aFilter = new AttributeFilter(reqAttributes, exclAttributes);
            String encodedUser = SCIM2Encoder.encodeUser(user, managerURL, aFilter);

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
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateUser(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource user = SCIM2Decoder.decodeUser(resourceString);

            UserResource createdUser = dataSource.createUser(user);

            String encodedUser = SCIM2Encoder.encodeUser(createdUser, managerURL);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = managerURL + SCIMConstants.USER_ENDPOINT + "/" + createdUser.getResourceId();
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
            @QueryParam("attributes") String reqAttributes, @QueryParam("excludedAttributes") String exclAttributes,
            @QueryParam("filter") String filter, @QueryParam("startIndex") String startIndex,
            @QueryParam("count") String count, @QueryParam("sortBy") String sortBy,
            @QueryParam("sortOrder") String sortOrder) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListUsers(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            int sIdx = (startIndex != null) ? Integer.parseInt(startIndex) : -1;
            int cnt = (count != null) ? Integer.parseInt(count) : -1;

            UserSearchResult searchResult = dataSource.listUsers(filter, sortBy, sortOrder, sIdx, cnt);

            AttributeFilter aFilter = new AttributeFilter(reqAttributes, exclAttributes);
            String encodedListedResource = SCIM2Encoder.encodeUserList(searchResult, managerURL, aFilter);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @POST
    @Path(".search")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String queryString) {
        /*
         * TODO implement
         */
        SchemaManagerException shEx = new SchemaManagerException("Unsupported operation",
                SCIMConstants.CODE_NOT_IMPLEMENTED);
        return SCIMProtocolCodec.responseFromException(shEx);
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
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeModifyUser(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            UserResource newUser = SCIM2Decoder.decodeUser(resourceString);
            newUser.setResourceId(id);

            UserResource updatedUser = dataSource.updateUser(newUser);

            String encodedUser = SCIM2Encoder.encodeUser(updatedUser, managerURL);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = managerURL + SCIMConstants.USER_ENDPOINT + "/" + updatedUser.getResourceId();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

}