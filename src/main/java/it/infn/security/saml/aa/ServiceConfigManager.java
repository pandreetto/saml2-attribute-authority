package it.infn.security.saml.aa;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.scim.core.SCIMCoreConstants;
import it.infn.security.scim.protocol.SCIMConstants;
import it.infn.security.scim.protocol.SCIMProtocolCodec;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.stream.JsonGenerator;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path(SCIMConstants.SRVCONFIG_ENDPOINT)
public class ServiceConfigManager {

    public ServiceConfigManager() {

    }

    @GET
    public Response getServiceConfig(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String format,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        Response result = null;
        JsonGenerator jGenerator = null;

        try {

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
            String locStr = configuration.getAuthorityURL() + "/manager" + SCIMConstants.SRVCONFIG_ENDPOINT;

            StringWriter sWriter = new StringWriter();
            jGenerator = Json.createGenerator(sWriter);
            jGenerator.writeStartObject();

            jGenerator.writeStartArray(SCIMCoreConstants.SCHEMAS);
            jGenerator.write(SCIMCoreConstants.SCIM2_SRVCONF_SCHEMA);
            jGenerator.writeEnd();

            jGenerator.writeStartObject(SCIMCoreConstants.META);
            jGenerator.write(SCIMCoreConstants.LOCATION, locStr);
            jGenerator.write(SCIMCoreConstants.RESOURCE_TYPE, "ServiceProviderConfig");
            /*
             * TODO creation and change time depends on the config file
             */
            jGenerator.writeEnd();

            jGenerator.writeStartObject("patch");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, false).writeEnd();

            jGenerator.writeStartObject("bulk");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, false).writeEnd();

            jGenerator.writeStartObject("filter");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, false).writeEnd();

            jGenerator.writeStartObject("changePassword");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, true).writeEnd();

            jGenerator.writeStartObject("sort");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, false).writeEnd();

            jGenerator.writeStartObject("eTag");
            jGenerator.write(SCIMCoreConstants.SUPPORTED, false).writeEnd();

            jGenerator.writeEnd().close();

            Map<String, String> httpHeaders = new HashMap<String, String>();
            httpHeaders.put(SCIMConstants.LOCATION_HEADER, locStr);
            httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);

            result = SCIMProtocolCodec.buildResponse(SCIMConstants.CODE_OK, httpHeaders, sWriter.toString());

        } catch (Exception ex) {
            result = SCIMProtocolCodec.responseFromException(ex);
        }

        return result;
    }

}