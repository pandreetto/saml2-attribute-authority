package it.infn.security.saml.utils.charon;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.wso2.charon.core.encoder.Decoder;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.InternalServerException;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon.core.schema.ServerSideValidator;
import org.wso2.charon.core.util.AttributeUtil;
import org.wso2.charon.core.util.CopyUtil;

public class UserResourceEndpoint
    extends org.wso2.charon.core.protocol.endpoints.UserResourceEndpoint {

    private static Logger logger = Logger.getLogger(UserResourceEndpoint.class.getName());

    @Override
    public SCIMResponse create(String scimObjectString, String inputFormat, String outputFormat,
            UserManager userManager, boolean isBulkUserAdd) {

        Encoder encoder = null;

        try {
            encoder = getEncoder(SCIMConstants.identifyFormat(outputFormat));
            Decoder decoder = getDecoder(SCIMConstants.identifyFormat(inputFormat));

            SCIMResourceSchema schema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();

            User user = (User) decoder.decodeResource(scimObjectString, schema, new User());

            validateCreatedSCIMObject(user, schema);

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
                String error = "Newly created User resource is null..";
                throw new InternalServerException(error);
            }

            return new SCIMResponse(ResponseCodeConstants.CODE_CREATED, encodedUser, httpHeaders);

        } catch (CharonException ex) {
            logger.log(Level.FINE, ex.getMessage(), ex);
            if (ex.getCode() == -1) {
                ex.setCode(ResponseCodeConstants.CODE_INTERNAL_SERVER_ERROR);
            }
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        } catch (AbstractCharonException ex) {
            logger.log(Level.FINE, ex.getMessage(), ex);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, ex);
        }
    }

    /*
     * Override ServerSideValidator#validateCreatedSCIMObject(AbstractSCIMObject, SCIMResourceSchema)
     * workaround for User#getGroups()
     */
    private void validateCreatedSCIMObject(AbstractSCIMObject scimObject, SCIMResourceSchema resourceSchema)
        throws CharonException {

        String id = UUID.randomUUID().toString();
        scimObject.setId(id);
        Date date = new Date();
        scimObject.setCreatedDate(AttributeUtil.parseDateTime(AttributeUtil.formatDateTime(date)));
        scimObject.setLastModified(AttributeUtil.parseDateTime(AttributeUtil.formatDateTime(date)));
        
        String location = "/" +  scimObject.getId();
        if (SCIMConstants.USER.equals(resourceSchema.getName())) {
            location = AbstractResourceEndpoint.getResourceEndpointURL(SCIMConstants.USER_ENDPOINT) + location;
        } else if (SCIMConstants.GROUP.equals(resourceSchema.getName())) {
            location = AbstractResourceEndpoint.getResourceEndpointURL(SCIMConstants.GROUP_ENDPOINT) + location;
            scimObject.setLocation(location);
        }
        scimObject.setLocation(location);

        ServerSideValidator.validateSCIMObjectForRequiredAttributes(scimObject, resourceSchema);
        ServerSideValidator.validateSchemaList(scimObject, resourceSchema);
    }

}