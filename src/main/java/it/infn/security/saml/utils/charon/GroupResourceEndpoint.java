package it.infn.security.saml.utils.charon;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.wso2.charon.core.encoder.Decoder;
import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.InternalServerException;
import org.wso2.charon.core.extensions.UserManager;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchema;
import org.wso2.charon.core.schema.ServerSideValidator;

public class GroupResourceEndpoint
    extends org.wso2.charon.core.protocol.endpoints.GroupResourceEndpoint {

    private static Logger logger = Logger.getLogger(GroupResourceEndpoint.class.getName());

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

}