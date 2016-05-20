package it.infn.security.saml.utils.charon;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

@Deprecated
public class UserResourceEndpoint {

    @Deprecated
    public Response get(String id, String format, DataSource dataSource)
        throws SchemaManagerException, DataSourceException {

        UserResource user = dataSource.getUser(id);

        String encodedUser = SCIMProtocolCodec.encodeUser(user, true, false);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

    }

    @Deprecated
    public Response listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format)
        throws SchemaManagerException, DataSourceException {

        UserSearchResult searchResult = dataSource.listUsers(filterString, sortBy, sortOrder, startIndex, count);

        String encodedListedResource = SCIMProtocolCodec.encodeUserSearchResult(searchResult);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

    }

    @Deprecated
    public Response create(String scimObjectString, String inputFormat, String outputFormat, DataSource dataSource,
            boolean isBulkUserAdd)
        throws SchemaManagerException, ConfigurationException, DataSourceException {

        UserResource user = SCIMProtocolCodec.decodeUser(scimObjectString, true);

        UserResource createdUser = dataSource.createUser(user, isBulkUserAdd);

        String encodedUser = SCIMProtocolCodec.encodeUser(createdUser, false, true);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getUserEndpointURL(createdUser.getUserId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedUser);

    }

    @Deprecated
    public Response create(String scimObjStr, String inFormat, String outFormat, DataSource dataSource)
        throws SchemaManagerException, ConfigurationException, DataSourceException {

        return create(scimObjStr, inFormat, outFormat, dataSource, false);

    }

    @Deprecated
    public Response delete(String id, DataSource dataSource, String outputFormat)
        throws DataSourceException {

        dataSource.deleteUser(id);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, null, null);

    }

    @Deprecated
    public Response updateWithPUT(String existingId, String scimObjectString, String inputFormat, String outputFormat,
            DataSource dataSource)
        throws SchemaManagerException, ConfigurationException, DataSourceException {

        UserResource oldUser = dataSource.getUser(existingId);
        UserResource newUser = SCIMProtocolCodec.decodeUser(scimObjectString, false);

        UserResource validatedUser = SCIMProtocolCodec.checkUserUpdate(oldUser, newUser);

        UserResource updatedUser = dataSource.updateUser(validatedUser);

        String encodedUser = SCIMProtocolCodec.encodeUser(updatedUser, false, true);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getUserEndpointURL(updatedUser.getUserId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

    }

    public Response updateWithPATCH(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, DataSource dataSource)
        throws SchemaManagerException, ConfigurationException {
        throw new SchemaManagerException("PATCH command not implemented");
    }

    private String getUserEndpointURL(String uId)
        throws ConfigurationException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        return configuration.getAuthorityURL() + "/manager" + SCIMConstants.USER_ENDPOINT + "/" + uId;

    }

}