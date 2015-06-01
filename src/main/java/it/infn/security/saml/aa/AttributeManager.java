package it.infn.security.saml.aa;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

@Path("/attributes")
public class AttributeManager {

    public AttributeManager() {

    }

    @GET
    @Path("/user/{id}")
    @Produces("application/json")
    public Response getUserAttributes(@PathParam("id")
    String userid) {
        ResponseBuilder result = Response.ok("{uid:\"testuser\"}");
        return result.build();
    }

}