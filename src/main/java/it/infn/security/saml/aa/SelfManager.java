package it.infn.security.saml.aa;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

@Path(SCIMConstants.SELF_ENDPOINT)
public class SelfManager {

    public SelfManager() {

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response getUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SchemaManagerException shEx = new SchemaManagerException("Unsupported operation on alias",
                SCIMConstants.CODE_NOT_IMPLEMENTED);
        return SCIMProtocolCodec.responseFromException(shEx);
    }

    @POST
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response createUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        SchemaManagerException shEx = new SchemaManagerException("Unsupported operation on alias",
                SCIMConstants.CODE_NOT_IMPLEMENTED);
        return SCIMProtocolCodec.responseFromException(shEx);
    }

    @DELETE
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response deleteUser(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        SchemaManagerException shEx = new SchemaManagerException("Unsupported operation on alias",
                SCIMConstants.CODE_NOT_IMPLEMENTED);
        return SCIMProtocolCodec.responseFromException(shEx);
    }

    @PUT
    @Produces(SCIMConstants.APPLICATION_SCIM)
    public Response updateUser(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String resourceString) {

        SchemaManagerException shEx = new SchemaManagerException("Unsupported operation on alias",
                SCIMConstants.CODE_NOT_IMPLEMENTED);
        return SCIMProtocolCodec.responseFromException(shEx);
    }
}