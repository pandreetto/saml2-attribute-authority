package it.infn.security.saml.utils.charon;

import org.wso2.charon.core.protocol.SCIMResponse;

import javax.ws.rs.core.Response;
import java.util.Map;

public class JAXRSResponseBuilder {

    @Deprecated
    public static Response buildResponse(int code, Map<String, String> httpHeaders, String message) {

        Response.ResponseBuilder responseBuilder = Response.status(code);

        if (httpHeaders != null && httpHeaders.size() != 0) {
            for (Map.Entry<String, String> entry : httpHeaders.entrySet()) {
                responseBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        if (message != null) {
            responseBuilder.entity(message);
        }

        return responseBuilder.build();
    }

    @Deprecated
    public static Response buildResponse(SCIMResponse scimResponse) {
        return buildResponse(scimResponse.getResponseCode(), scimResponse.getHeaderParameterMap(),
                scimResponse.getResponseMessage());
    }

}