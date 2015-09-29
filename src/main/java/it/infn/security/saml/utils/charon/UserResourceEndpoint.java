package it.infn.security.saml.utils.charon;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.UserSearchResult;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;

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
import org.wso2.charon.core.exceptions.ResourceNotFoundException;
import org.wso2.charon.core.extensions.Storage;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.ServerSideValidator;
import org.wso2.charon.core.util.CopyUtil;

public class UserResourceEndpoint
    extends AbstractResourceEndpoint {

    private static Logger logger = Logger.getLogger(UserResourceEndpoint.class.getName());

    @Override
    public SCIMResponse get(String id, String format, UserManager userManager) {

        Encoder encoder = null;
        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(format));

            User user = ((UserManager) userManager).getUser(id);
            if (user == null) {
                throw new ResourceNotFoundException("User not found in the user store.");
            }

            SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();
            ServerSideValidator.validateRetrievedSCIMObject(user, schema);
            String encodedUser = encoder.encodeSCIMObject(user);
            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedUser, httpHeaders);

        } catch (SchemaManagerException schEx) {
            logger.log(Level.FINE, schEx.getMessage());
            CharonException wrapper = new CharonException("Schema unsupported");
            return AbstractResourceEndpoint.encodeSCIMException(encoder, wrapper);
        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    public SCIMResponse listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format) {

        Encoder encoder = null;
        try {

            encoder = getEncoder(SCIMConstants.identifyFormat(format));

            UserSearchResult searchResult = dataSource.listUsers(filterString, sortBy, sortOrder, startIndex, count);
            ListedResource listedResource = buildListedResource(searchResult);
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

    public SCIMResponse create(String scimObjectString, String inputFormat, String outputFormat,
            UserManager userManager, boolean isBulkUserAdd) {

        Encoder encoder = null;

        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            Decoder decoder = getDecoder(SCIMConstants.identifyFormat(inputFormat));

            SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();

            User user = (User) decoder.decodeResource(scimObjectString, schema, new User());

            ServerSideValidator.validateCreatedSCIMObject(user, schema);
            User createdUser = userManager.createUser(user, isBulkUserAdd);

            String encodedUser;
            Map<String, String> httpHeaders = new HashMap<String, String>();
            if (createdUser != null) {
                User copiedUser = (User) CopyUtil.deepCopy(createdUser);

                ServerSideValidator.removePasswordOnReturn(copiedUser);
                encodedUser = encoder.encodeSCIMObject(copiedUser);
                httpHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(SCIMConstants.USER_ENDPOINT)
                        + "/" + createdUser.getId());
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

            } else {
                throw new InternalServerException("Newly created User resource is null");
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED, encodedUser, httpHeaders);

        } catch (SchemaManagerException schEx) {
            logger.log(Level.FINE, schEx.getMessage());
            CharonException wrapper = new CharonException("Schema unsupported");
            return AbstractResourceEndpoint.encodeSCIMException(encoder, wrapper);
        } catch (AbstractCharonException ex) {
            if (ex instanceof CharonException && ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }

    }

    @Override
    public SCIMResponse create(String scimObjStr, String inFormat, String outFormat, UserManager userManager) {

        return create(scimObjStr, inFormat, outFormat, userManager, false);
    }

    @Override
    public SCIMResponse delete(String id, Storage storage, String outputFormat) {
        Encoder encoder = null;
        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            if (storage instanceof UserManager) {
                ((UserManager) storage).deleteUser(id);
            } else {
                throw new InternalServerException("Storage handler is not an implementation of UserManager");
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
    public SCIMResponse updateWithPUT(String existingId, String scimObjectString, String inputFormat,
            String outputFormat, UserManager userManager) {

        Encoder encoder = null;
        Decoder decoder = null;

        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            decoder = getDecoder(SCIMConstants.identifyFormat(inputFormat));

            SCIMResourceSchema schema = SchemaManagerFactory.getManager().getUserSchema();

            User user = (User) decoder.decodeResource(scimObjectString, schema, new User());
            User updatedUser = null;
            if (userManager != null) {
                User oldUser = userManager.getUser(existingId);
                if (oldUser != null) {
                    User validatedUser = (User) ServerSideValidator.validateUpdatedSCIMObject(oldUser, user, schema);
                    updatedUser = userManager.updateUser(validatedUser);

                } else {
                    throw new ResourceNotFoundException("No user exists with the given id: " + existingId);
                }

            } else {
                throw new InternalServerException("Provided user manager handler is null.");
            }

            String encodedUser;
            Map<String, String> httpHeaders = new HashMap<String, String>();
            if (updatedUser != null) {
                User copiedUser = (User) CopyUtil.deepCopy(updatedUser);
                ServerSideValidator.removePasswordOnReturn(copiedUser);
                encodedUser = encoder.encodeSCIMObject(copiedUser);
                httpHeaders.put(SCIMConstants.LOCATION_HEADER, getResourceEndpointURL(SCIMConstants.USER_ENDPOINT)
                        + "/" + updatedUser.getId());
                httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, outputFormat);

            } else {
                throw new InternalServerException("Updated User resource is null");
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedUser, httpHeaders);

        } catch (SchemaManagerException schEx) {
            logger.log(Level.FINE, schEx.getMessage());
            CharonException wrapper = new CharonException("Schema unsupported");
            return AbstractResourceEndpoint.encodeSCIMException(encoder, wrapper);
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
}