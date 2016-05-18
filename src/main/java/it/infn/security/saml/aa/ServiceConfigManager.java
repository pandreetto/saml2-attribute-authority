package it.infn.security.saml.aa;

import it.infn.security.scim.protocol.SCIMConstants;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

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