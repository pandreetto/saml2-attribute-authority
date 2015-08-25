package it.infn.security.saml.ocp;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

@Path("/attributes")
public class SPIDAttributeManager {

    public SPIDAttributeManager() {

    }

    @GET
    @Produces("application/json")
    public Response getAttributeKeys() {
        ResponseBuilder result = Response.ok("{keys:[]}");
        return result.build();
    }

    @GET
    @Path("{attrKey}")
    @Produces("application/json")
    public Response getAttributesByKey(@PathParam("attrKey") String attrKey) {
        ResponseBuilder result = Response.ok("{attributes:[]}");
        return result.build();
    }

    @DELETE
    @Path("{attrKey}")
    @Produces("application/json")
    public Response deleteAllAttributesByKey(@PathParam("attrKey") String attrKey) {
        return null;
    }

    @DELETE
    @Path("{attrKey}/{attrValue}")
    @Produces("application/json")
    public Response deleteAttribute(@PathParam("attrKey") String attrKey, @PathParam("attrValue") String attrValue) {
        return null;
    }

    @POST
    @Produces("application/json")
    public Response createAttribute(String payload) {
        return null;
    }

}