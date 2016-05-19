package it.infn.security.scim.protocol;

import it.infn.security.saml.iam.AccessManagerException;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;

public class SCIMProtocolCodec {

    private static Logger logger = Logger.getLogger(SCIMProtocolCodec.class.getName());

    public static Response responseFromException(Exception ex) {
        AbstractCharonException chEx = null;

        logger.log(Level.FINE, "Detected exception " + ex.getMessage(), ex);

        if (ex instanceof AbstractCharonException) {

            chEx = (AbstractCharonException) ex;
            if (chEx.getCode() == -1) {
                chEx.setCode(SCIMConstants.CODE_INTERNAL_SERVER_ERROR);
            }

        } else if (ex instanceof AccessManagerException) {

            int code = 401;
            String msg = "Authorization failure";
            chEx = new AbstractCharonException(code, msg);

        } else {

            int code = 500;
            String msg = "Internal server error: " + ex.getMessage();
            chEx = new AbstractCharonException(code, msg);

        }

        Encoder encoder = new JSONEncoder();
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_JSON);
        return buildResponse(chEx.getCode(), httpHeaders, encoder.encodeSCIMException(chEx));
    }

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

}