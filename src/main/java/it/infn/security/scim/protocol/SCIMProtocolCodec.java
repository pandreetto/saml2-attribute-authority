package it.infn.security.scim.protocol;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;

import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.core.SCIM2Encoder;

public class SCIMProtocolCodec {

    private static Logger logger = Logger.getLogger(SCIMProtocolCodec.class.getName());

    public static Response responseFromException(Exception ex) {

        logger.log(Level.FINE, "Detected exception " + ex.getMessage(), ex);

        int code = SCIMConstants.CODE_INTERNAL_SERVER_ERROR;
        String message = null;

        if (ex instanceof CodedException) {
            CodedException cEx = (CodedException) ex;
            code = cEx.getCode();
            message = cEx.getMessage();
        } else {
            message = "Internal server error";
        }

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, SCIMConstants.APPLICATION_SCIM);
        return buildResponse(code, httpHeaders, SCIM2Encoder.encodeException(code, message));
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

    public static void checkAcceptedFormat(String format)
        throws SchemaManagerException {
        if (format == null || format.equals("*/*"))
            return;
        if (!format.contains(SCIMConstants.APPLICATION_SCIM) && !format.contains(SCIMConstants.APPLICATION_JSON)) {
            logger.severe("Wrong accepted format: " + format);
            throw new SchemaManagerException("Unsupported accepted format " + format);
        }
    }

    public static void checkContentFormat(String format)
        throws SchemaManagerException {
        if (format == null)
            throw new SchemaManagerException("Missing content type format");
        if (!format.contains(SCIMConstants.APPLICATION_SCIM) && !format.contains(SCIMConstants.APPLICATION_JSON)) {
            logger.severe("Wrong content type format: " + format);
            throw new SchemaManagerException("Unsupported content type format " + format);
        }
    }
    
    public static String[] parseIfMatch(String mList) {
        if(mList!=null && mList.length()>0)
            return mList.split(",");
        return null;
    }
    
    public static boolean checkIfNoneMatch(String version, String mList) {

        return !checkIfMatch(version, mList);

    }

    public static boolean checkIfMatch(String version, String mList) {
        logger.info("Called check match with " + mList);
        if (mList == null || mList.length() == 0)
            return false;

        for (String tmps : mList.split(",")) {
            logger.info("Checking " + tmps + " against " + version);
            if (tmps.trim().equals(version))
                return true;
        }

        return false;
    }

}