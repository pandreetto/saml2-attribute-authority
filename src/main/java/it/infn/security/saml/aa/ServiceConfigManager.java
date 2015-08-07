package it.infn.security.saml.aa;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import org.wso2.charon.core.schema.SCIMConstants;

@Path("/ServiceProviderConfigs")
public class ServiceConfigManager {
    
    public ServiceConfigManager() {
        
    }
    
    @GET
    public Response getServiceConfig(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization){
        
        return null;
        
    }
    
}