package it.infn.security.saml.aa;

import java.util.Date;
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
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.scim.core.SCIM2Decoder;
import it.infn.security.scim.core.SCIM2Encoder;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

@Path(SCIMConstants.GROUP_ENDPOINT)
public class GroupResourceManager {

    private static final Logger logger = Logger.getLogger(GroupResourceManager.class.getName());

    public GroupResourceManager() {

    }

    @GET
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getGroup(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            GroupResource group = dataSource.getGroup(id);

            String encodedGroup = SCIM2Encoder.encodeGroup(group, managerURL);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);
            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response createGroup(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
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
            accessManager.authorizeCreateGroup(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            GroupResource group = SCIM2Decoder.decodeGroup(resourceString);

            GroupResource createdGroup = dataSource.createGroup(group);

            String encodedGroup = SCIM2Encoder.encodeGroup(createdGroup, managerURL);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = managerURL + SCIMConstants.GROUP_ENDPOINT + "/" + createdGroup.getResourceId();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedGroup);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @DELETE
    @Path("{id}")
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response deleteGroup(@PathParam(SCIMConstants.ID) String id,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            dataSource.deleteGroup(id);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_NO_CONTENT, null, null);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getGroup(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization,
            @QueryParam("attributes") String searchAttribute, @QueryParam("filter") String filter,
            @QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
            @QueryParam("sortBy") String sortBy, @QueryParam("sortOrder") String sortOrder) {

        Response result = null;
        try {

            SCIMProtocolCodec.checkAcceptedFormat(format);

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String managerURL = configuration.getAuthorityURL() + "/manager";

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListGroups(requester);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            if (searchAttribute != null) {
                logger.severe("Unsupported query with attributes");
                throw new CodedException(SCIMConstants.DESC_BAD_REQUEST_GET);
            } else {
                int sIdx = (startIndex != null) ? Integer.parseInt(startIndex) : -1;
                int cnt = (count != null) ? Integer.parseInt(count) : -1;

                GroupSearchResult returnedGroups = dataSource.listGroups(filter, sortBy, sortOrder, sIdx, cnt);

                String encodedListedResource = SCIM2Encoder.encodeGroupList(returnedGroups, managerURL);

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
    public Response updateGroup(@PathParam(SCIMConstants.ID) String id,
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
            accessManager.authorizeModifyGroup(requester, id);

            DataSource dataSource = DataSourceFactory.getDataSource().getProxyDataSource(requester);

            GroupResource oldGroup = dataSource.getGroup(id);
            GroupResource newGroup = SCIM2Decoder.decodeGroup(resourceString);

            newGroup.setResourceId(oldGroup.getResourceId());
            newGroup.setResourceCreationDate(oldGroup.getResourceCreationDate());
            newGroup.setResourceChangeDate(new Date());
            newGroup.setResourceVersion(oldGroup.getResourceVersion());

            GroupResource updatedGroup = dataSource.updateGroup(oldGroup, newGroup);

            String encodedGroup = SCIM2Encoder.encodeGroup(updatedGroup, managerURL);

            Map<String, String> httpHeaders = new HashMap<String, String>();
            String locStr = managerURL + SCIMConstants.GROUP_ENDPOINT + "/" + updatedGroup.getResourceId();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

        } catch (Exception ex) {

            result = SCIMProtocolCodec.responseFromException(ex);

        }

        return result;

    }

}