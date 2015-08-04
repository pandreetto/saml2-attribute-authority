package it.infn.security.saml.utils.charon;

import it.infn.security.saml.datasource.DataSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.ResourceNotFoundException;
import org.wso2.charon.core.objects.ListedResource;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;

public class UserResourceEndpoint
    extends org.wso2.charon.core.protocol.endpoints.UserResourceEndpoint {

    private static Logger logger = Logger.getLogger(UserResourceEndpoint.class.getName());

    public SCIMResponse listByParams(String filterString, String sortBy, String sortOrder, int startIndex, int count,
            DataSource dataSource, String format) {
        
        Encoder encoder = null;
        try {
            
            encoder = getEncoder(SCIMConstants.identifyFormat(format));
            
            List<User> returnedUsers = dataSource.listUsers(filterString, sortBy, sortOrder, startIndex, count);
            if (returnedUsers == null || returnedUsers.isEmpty()) {
                String error = "Users not found in the user store for the filter: " + filterString;
                throw new ResourceNotFoundException(error);
            }
            
            ListedResource listedResource = createListedResource(returnedUsers);
            String encodedListedResource = encoder.encodeSCIMObject(listedResource);
            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
            return new SCIMResponse(ResponseCodeConstants.CODE_OK, encodedListedResource, httpHeaders);
            
        } catch(AbstractCharonException chEx) {
            logger.log(Level.SEVERE, chEx.getMessage(), chEx);
            return AbstractResourceEndpoint.encodeSCIMException(encoder, chEx);
        }
    }
}