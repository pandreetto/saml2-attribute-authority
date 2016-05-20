package it.infn.security.saml.utils.charon;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

@Deprecated
public class GroupResourceEndpoint {

    @Deprecated
    public Response get(String id, String format, DataSource dataSource)
        throws SchemaManagerException, DataSourceException {

        GroupResource group = dataSource.getGroup(id);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(group, true);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

    }

    @Deprecated
    public Response create(String scimObjectString, String inFormat, String outFormat, DataSource dataSource)
        throws SchemaManagerException, ConfigurationException, DataSourceException {

        GroupResource group = SCIMProtocolCodec.decodeGroup(scimObjectString, true);

        GroupResource createdGroup = dataSource.createGroup(group);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(createdGroup, false);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(createdGroup.getGroupId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedGroup);

    }

    @Deprecated
    public Response delete(String id, DataSource dataSource, String outputFormat)
        throws DataSourceException {

        dataSource.deleteGroup(id);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, null, null);

    }

    @Deprecated
    public Response listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format)
        throws SchemaManagerException, DataSourceException {

        GroupSearchResult returnedGroups = dataSource.listGroups(filterString, sortBy, sortOrder, startIndex, count);

        String encodedListedResource = SCIMProtocolCodec.encodeGroupSearchResult(returnedGroups);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

    }

    @Deprecated
    public Response updateWithPUT(String existingId, String scimObjectString, String inputFormat, String outputFormat,
            DataSource dataSource)
        throws SchemaManagerException, ConfigurationException, DataSourceException {

        GroupResource oldGroup = dataSource.getGroup(existingId);
        GroupResource newGroup = SCIMProtocolCodec.decodeGroup(scimObjectString, false);
        GroupResource validatedGroup = SCIMProtocolCodec.checkGroupUpdate(oldGroup, newGroup);

        GroupResource updatedGroup = dataSource.updateGroup(oldGroup, validatedGroup);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(updatedGroup, false);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(updatedGroup.getGroupId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

    }

    public Response updateWithPATCH(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, DataSource dataSource)
        throws SchemaManagerException, ConfigurationException {
        throw new SchemaManagerException("PATCH command not implemented");
    }

    private String getGroupEndpointURL(String gId)
        throws ConfigurationException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        return configuration.getAuthorityURL() + "/manager" + SCIMConstants.GROUP_ENDPOINT + "/" + gId;

    }

}