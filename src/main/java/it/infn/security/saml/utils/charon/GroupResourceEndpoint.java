package it.infn.security.saml.utils.charon;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupSearchResult;
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
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.exceptions.ResourceNotFoundException;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.ServerSideValidator;

public class GroupResourceEndpoint {

    private static Logger logger = Logger.getLogger(GroupResourceEndpoint.class.getName());

    public Response get(String id, String format, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, DataSourceException {

        Group group = dataSource.getGroup(id);
        if (group == null) {
            String message = "Group not found in the user store.";
            throw new ResourceNotFoundException(message);
        }

        SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();
        ServerSideValidator.validateRetrievedSCIMObject(group, groupSchema);

        JSONEncoder encoder = new JSONEncoder();
        String encodedGroup = encoder.encodeSCIMObject(group);

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, encodedGroup);

    }

    public Response create(String scimObjectString, String inFormat, String outFormat, DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();
        JSONDecoder decoder = new JSONDecoder();

        SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();

        Group group = (Group) decoder.decodeResource(scimObjectString, groupSchema, new Group());

        ServerSideValidator.validateCreatedSCIMObject(group, groupSchema);
        Group createdGroup = dataSource.createGroup(group);

        String encodedGroup;
        Map<String, String> httpHeaders = new HashMap<String, String>();
        if (createdGroup != null) {

            encodedGroup = encoder.encodeSCIMObject(createdGroup);
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(createdGroup.getId()));
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outFormat);

        } else {
            String message = "Newly created Group resource is null..";
            throw new InternalServerException(message);
        }

        return SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_CREATED, httpHeaders, encodedGroup);

    }

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

    public Response updateWithPUT(String existingId, String scimObjectString, String inputFormat, String outputFormat,
            DataSource dataSource)
        throws SchemaManagerException, AbstractCharonException, ConfigurationException, DataSourceException {

        JSONEncoder encoder = new JSONEncoder();
        JSONDecoder decoder = new JSONDecoder();

        SCIMResourceSchema groupSchema = SchemaManagerFactory.getManager().getGroupSchema();

        Group group = (Group) decoder.decodeResource(scimObjectString, groupSchema, new Group());
        Group updatedGroup = null;
        Group oldGroup = dataSource.getGroup(existingId);
        if (oldGroup != null) {
            Group validatedGroup = (Group) ServerSideValidator.validateUpdatedSCIMObject(oldGroup, group, groupSchema);
            updatedGroup = dataSource.updateGroup(oldGroup, validatedGroup);
        } else {
            String message = "No group exists with the given id: " + existingId;
            throw new ResourceNotFoundException(message);
        }

        String encodedGroup;
        Map<String, String> httpHeaders = new HashMap<String, String>();
        if (updatedGroup != null) {

            encodedGroup = encoder.encodeSCIMObject(updatedGroup);
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, getGroupEndpointURL(updatedGroup.getId()));
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

        } else {
            String message = "Updated User resource is null..";
            throw new InternalServerException(message);
        }

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