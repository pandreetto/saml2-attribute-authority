package it.infn.security.saml.utils;

import org.wso2.charon.core.encoder.Encoder;
import org.wso2.charon.core.encoder.json.JSONEncoder;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.protocol.SCIMResponse;
import org.wso2.charon.core.protocol.endpoints.AbstractResourceEndpoint;
import org.wso2.charon.core.schema.SCIMConstants;

public class SCIMUtils {

    public static String normalizeFormat(String format) {
        if (format == null) {
            return SCIMConstants.APPLICATION_JSON;
        }

        String result = format.trim();
        if (result.equals("*/*")) {
            return SCIMConstants.APPLICATION_JSON;
        }

        return result;
    }

    public static Encoder getEncoder(String format) {

        format = normalizeFormat(format);

        String formatType = SCIMConstants.identifyFormat(format);
        if (SCIMConstants.JSON == formatType || formatType == null)
            return new JSONEncoder();

        throw new IllegalArgumentException("Encoder unsupported " + format);
    }

    public static SCIMResponse responseFromException(AbstractCharonException chEx, String format) {

        Encoder encoder = getEncoder(format);
        return AbstractResourceEndpoint.encodeSCIMException(encoder, chEx);

    }

    public static SCIMResponse responseFromException(Exception ex, String format) {

        int code = 500;
        String msg = "Internal server error (" + ex.getMessage() + ")";

        return responseFromException(new AbstractCharonException(code, msg), format);

    }
}
