package it.infn.security.saml.utils.charon;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.GroupSearchResult;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.encoder.Decoder;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.InternalServerException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.exceptions.ResourceNotFoundException;
import org.wso2.charon.core.extensions.Storage;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.ServerSideValidator;

public class GroupResourceEndpoint
    extends AbstractResourceEndpoint {

    private static Logger logger = Logger.getLogger(GroupResourceEndpoint.class.getName());

    @Override
    public SCIMResponse get(String id, String format, UserManager userManager) {

        Encoder encoder = null;
        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(format));

            Group group = ((UserManager) userManager).getGroup(id);

            if (group == null) {
                String message = "Group not found in the user store.";
                throw new ResourceNotFoundException(message);
            }
            ServerSideValidator.validateRetrievedSCIMObject(group, SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA);
            String encodedGroup = encoder.encodeSCIMObject(group);
            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedGroup, httpHeaders);

        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    @Override
    public SCIMResponse create(String scimObjectString, String inputFormat, String outputFormat, UserManager userManager) {

        Encoder encoder = null;
        Decoder decoder = null;

        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            decoder = getDecoder(SCIMConstants.identifyFormat(inputFormat));

            SCIMResourceSchema groupSchema = SCIMGroupSchemaManager.getSchema();

            Group group = (Group) decoder.decodeResource(scimObjectString, groupSchema, new Group());

            ServerSideValidator.validateCreatedSCIMObject(group, groupSchema);
            Group createdGroup = ((UserManager) userManager).createGroup(group);

            String encodedGroup;
            Map<String, String> httpHeaders = new HashMap<String, String>();
            if (createdGroup != null) {

                encodedGroup = encoder.encodeSCIMObject(createdGroup);
                httpHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(SCIMConstants.GROUP_ENDPOINT)
                        + "/" + createdGroup.getId());
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

            } else {
                String message = "Newly created Group resource is null..";
                throw new InternalServerException(message);
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED, encodedGroup, httpHeaders);

        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    @Override
    public SCIMResponse delete(String id, Storage storage, String outputFormat) {
        Encoder encoder = null;
        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            if (storage instanceof UserManager) {
                ((UserManager) storage).deleteGroup(id);
            } else {
                String message = "Provided storage handler is not an implementation of UserManager";
                throw new InternalServerException(message);
            }
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, null, null);
        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    @Override
    public SCIMResponse listByAttribute(String searchAttribute, UserManager userManager, String format) {
        return null;
    }

    @Override
    public SCIMResponse listByFilter(String filterString, UserManager userManager, String format) {
        return null;
    }

    @Override
    public SCIMResponse listBySort(String sortBy, String sortOrder, UserManager usermanager, String format) {
        return null;
    }

    @Override
    public SCIMResponse listWithPagination(int startIndex, int count, UserManager userManager, String format) {
        return null;
    }

    @Override
    public SCIMResponse list(UserManager userManager, String format) {
        return null;
    }

    public SCIMResponse listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format) {

        Encoder encoder = null;
        try {

            encoder = getEncoder(SCIMConstants.identifyFormat(format));

            GroupSearchResult returnedGroups = dataSource
                    .listGroups(filterString, sortBy, sortOrder, startIndex, count);
            if (returnedGroups == null || returnedGroups.isEmpty()) {
                String error = "Groups not found in the user store for the filter: " + filterString;
                throw new ResourceNotFoundException(error);
            }

            ListedResource listedResource = createListedResource(returnedGroups);
            String encodedListedResource = encoder.encodeSCIMObject(listedResource);
            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, httpHeaders);

        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    @Override
    public SCIMResponse updateWithPUT(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, UserManager userManager) {
        Encoder encoder = null;
        Decoder decoder = null;

        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            decoder = getDecoder(SCIMConstants.identifyFormat(inputFormat));

            Group group = (Group) decoder.decodeResource(scimObjectString, SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA,
                    new Group());
            Group updatedGroup = null;
            if (userManager != null) {
                Group oldGroup = userManager.getGroup(existingId);
                if (oldGroup != null) {
                    Group validatedGroup = (Group) ServerSideValidator.validateUpdatedSCIMObject(oldGroup, group,
                            SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA);
                    updatedGroup = userManager.updateGroup(oldGroup, validatedGroup);
                } else {
                    String message = "No group exists with the given id: " + existingId;
                    throw new ResourceNotFoundException(message);
                }

            } else {
                String message = "Provided User manager handler is null.";
                throw new InternalServerException(message);
            }

            String encodedGroup;
            Map<String, String> httpHeaders = new HashMap<String, String>();
            if (updatedGroup != null) {

                encodedGroup = encoder.encodeSCIMObject(updatedGroup);
                httpHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(SCIMConstants.USER_ENDPOINT)
                        + "/" + updatedGroup.getId());
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

            } else {
                String message = "Updated User resource is null..";
                throw new InternalServerException(message);
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedGroup, httpHeaders);

        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    @Override
    public SCIMResponse updateWithPATCH(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, UserManager userManager) {
        return null;
    }

    private ListedResource createListedResource(GroupSearchResult searchResult)
        throws CharonException, NotFoundException {
        ListedResource listedResource = new ListedResource();
        listedResource.setTotalResults(searchResult.getTotalResults());
        for (Group group : searchResult.getGroupList()) {
            if (group != null) {
                Map<String, Attribute> attributesOfGroupResource = group.getAttributeList();
                listedResource.setResources(attributesOfGroupResource);
            }
        }
        return listedResource;
    }

}