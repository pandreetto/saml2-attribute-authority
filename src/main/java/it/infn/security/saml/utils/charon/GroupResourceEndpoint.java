package it.infn.security.saml.utils.charon;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.ListedResource;

public class GroupResourceEndpoint {

    private static Logger logger = Logger.getLogger(GroupResourceEndpoint.class.getName());

    @Deprecated
    public Response get(String id, String format, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, DataSourceException {

        Group group = dataSource.getGroup(id);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(group, true);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

    }

    @Deprecated
    public Response create(String scimObjectString, String inFormat, String outFormat, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        Group group = SCIMProtocolCodec.decodeGroup(scimObjectString, true);

        Group createdGroup = dataSource.createGroup(group);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(createdGroup, false);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(createdGroup.getId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedGroup);

    }

    @Deprecated
    public Response delete(String id, DataSource dataSource, String outputFormat)
        throws AbstractCharonException, DataSourceException {

        dataSource.deleteGroup(id);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, null, null);

    }

    public Response listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format)
        throws AbstractCharonException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();

        GroupSearchResult returnedGroups = dataSource.listGroups(filterString, sortBy, sortOrder, startIndex, count);
        ListedResource listedResource = createListedResource(returnedGroups);
        String encodedListedResource = encoder.encodeSCIMObject(listedResource);
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedListedResource);

    }

    @Deprecated
    public Response updateWithPUT(String existingId, String scimObjectString, String inputFormat, String outputFormat,
            DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        Group oldGroup = dataSource.getGroup(existingId);
        Group newGroup = SCIMProtocolCodec.decodeGroup(scimObjectString, false);
        Group validatedGroup = SCIMProtocolCodec.checkGroupUpdate(oldGroup, newGroup);

        Group updatedGroup = dataSource.updateGroup(oldGroup, validatedGroup);

        String encodedGroup = SCIMProtocolCodec.encodeGroup(updatedGroup, false);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(updatedGroup.getId()));
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

    }

    public Response updateWithPATCH(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException {
        throw new SchemaManagerException("PATCH command not implemented");
    }

    private ListedResource createListedResource(GroupSearchResult searchResult)
        throws CharonException, NotFoundException {
        ListedResource listedResource = new ListedResource();
        if (searchResult == null || searchResult.isEmpty()) {
            listedResource.setTotalResults(0);
        } else {
            listedResource.setTotalResults(searchResult.getTotalResults());
            for (Group group : searchResult.getGroupList()) {
                if (group != null) {
                    Map<String, Attribute> attributesOfGroupResource = group.getAttributeList();
                    listedResource.setResources(attributesOfGroupResource);
                }
            }
        }
        return listedResource;
    }

    private String getGroupEndpointURL(String gId)
        throws ConfigurationException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        return configuration.getAuthorityURL() + "/manager" + SCIMConstants.GROUP_ENDPOINT + "/" + gId;

    }

}