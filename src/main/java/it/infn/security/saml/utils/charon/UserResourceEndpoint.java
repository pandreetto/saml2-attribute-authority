package it.infn.security.saml.utils.charon;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.encoder.json.JSONDecoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.InternalServerException;
import org.wso2.charon.core.exceptions.ResourceNotFoundException;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.ServerSideValidator;
import org.wso2.charon.core.util.CopyUtil;

public class UserResourceEndpoint {

    private static Logger logger = Logger.getLogger(UserResourceEndpoint.class.getName());

    public Response get(String id, String format, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();

        User user = dataSource.getUser(id);
        if (user == null) {
            throw new ResourceNotFoundException("User not found in the user store.");
        }

        SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
        ServerSideValidator.validateRetrievedSCIMObject(user, schema);
        String encodedUser = encoder.encodeSCIMObject(user);
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

    }

    public Response listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format)
        throws AbstractCharonException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();

        UserSearchResult searchResult = dataSource.listUsers(filterString, sortBy, sortOrder, startIndex, count);
        ListedResource listedResource = buildListedResource(searchResult);
        String encodedListedResource = encoder.encodeSCIMObject(listedResource);
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

    }

    public Response create(String scimObjectString, String inputFormat, String outputFormat, DataSource dataSource,
            boolean isBulkUserAdd)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();
        JSONDecoder decoder = new JSONDecoder();

        SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();

        User user = (User) decoder.decodeResource(scimObjectString, schema, new User());

        ServerSideValidator.validateCreatedSCIMObject(user, schema);
        User createdUser = dataSource.createUser(user, isBulkUserAdd);

        String encodedUser;
        Map<String, String> httpHeaders = new HashMap<String, String>();
        if (createdUser != null) {
            User copiedUser = (User) CopyUtil.deepCopy(createdUser);

            ServerSideValidator.removePasswordOnReturn(copiedUser);
            encodedUser = encoder.encodeSCIMObject(copiedUser);
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, getUserEndpointURL(createdUser.getId()));
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        } else {
            throw new InternalServerException("Newly created User resource is null");
        }

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedUser);

    }

    public Response create(String scimObjStr, String inFormat, String outFormat, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        return create(scimObjStr, inFormat, outFormat, dataSource, false);

    }

    public Response delete(String id, DataSource dataSource, String outputFormat)
        throws AbstractCharonException, DataSourceException {

        dataSource.deleteUser(id);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, null, null);

    }

    public Response updateWithPUT(String existingId, String scimObjectString, String inputFormat, String outputFormat,
            DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();
        JSONDecoder decoder = new JSONDecoder();

        SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();

        User user = (User) decoder.decodeResource(scimObjectString, schema, new User());
        User updatedUser = null;
        User oldUser = dataSource.getUser(existingId);
        if (oldUser != null) {
            User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(oldUser, user, schema);
            updatedUser = dataSource.updateUser(validatedUser);

        } else {
            throw new ResourceNotFoundException("No user exists with the given id: " + existingId);
        }

        String encodedUser;
        Map<String, String> httpHeaders = new HashMap<String, String>();
        if (updatedUser != null) {
            User copiedUser = (User) CopyUtil.deepCopy(updatedUser);
            ServerSideValidator.removePasswordOnReturn(copiedUser);
            encodedUser = encoder.encodeSCIMObject(copiedUser);
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, getUserEndpointURL(updatedUser.getId()));
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        } else {
            throw new InternalServerException("Updated User resource is null");
        }

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedUser);

    }

    public Response updateWithPATCH(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException {
        throw new SchemaManagerException("PATCH command not implemented");
    }

    private ListedResource buildListedResource(UserSearchResult searchResult)
        throws CharonException {
        ListedResource listedResource = new ListedResource();
        if (searchResult == null || searchResult.isEmpty()) {
            listedResource.setTotalResults(0);
        } else {
            listedResource.setTotalResults(searchResult.getTotalResults());
            for (User user : searchResult.getUserList()) {
                Map<String, Attribute> userAttributes = user.getAttributeList();
                listedResource.setResources(userAttributes);
            }
        }
        return listedResource;
    }

    private String getUserEndpointURL(String uId)
        throws ConfigurationException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        return configuration.getAuthorityURL() + "/manager" + SCIMConstants.USER_ENDPOINT + "/" + uId;

    }

}