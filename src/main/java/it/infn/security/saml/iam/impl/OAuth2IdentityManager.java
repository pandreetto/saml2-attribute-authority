package it.infn.security.saml.iam.impl;

import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.HttpsURLConnection;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import it.infn.security.saml.aa.AttributeAuthorityContext;
import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerException;

public class OAuth2IdentityManager
    implements IdentityManager {

    private static final Logger logger = Logger.getLogger(TLSIdentityManager.class.getName());

    public static final String AUTHZ_SERVER_URL = "authentication.oauth2.introspect.url";

    private String authzSrvUrl;

    public OAuth2IdentityManager() {

    }

    public int getLoadPriority() {
        return 0;
    }

    public void init()
        throws IdentityManagerException {

        try {

            AuthorityConfiguration authConf = AuthorityConfigurationFactory.getConfiguration();
            authzSrvUrl = authConf.getAccessManagerParam(AUTHZ_SERVER_URL, null);

        } catch (CodedException cEx) {
            throw new IdentityManagerException(cEx.getMessage(), cEx.getCode());
        }
    }

    /*
     * Implememtation based on RFC 7662 OpenAM as authz server
     * https://backstage.forgerock.com/#!/docs/openam/13/admin-guide/chap-oauth2
     * http://stackoverflow.com/questions/12296017/how-to-validate-an-oauth-2-0-access-token-for-a-resource-server
     */
    private Subject validateToken(String token)
        throws IdentityManagerException {

        if (authzSrvUrl != null) {

            HttpsURLConnection urlConn = null;
            JsonReader jReader = null;
            DataOutputStream dataStream = null;

            try {

                URI location = new URI(authzSrvUrl);

                urlConn = (HttpsURLConnection) location.toURL().openConnection();
                urlConn.setRequestMethod("POST");
                urlConn.setRequestProperty("User-Agent", "INFN SPID Attribute Authority");
                urlConn.setDoOutput(true);

                /*
                 * TODO missing client authentication
                 */

                dataStream = new DataOutputStream(urlConn.getOutputStream());
                dataStream.writeBytes("token=" + token + "&token_type_hint=access_token");
                dataStream.flush();
                dataStream.close();

                int respCode = urlConn.getResponseCode();
                if (respCode >= 400) {
                    throw new IdentityManagerException("Code " + respCode + " from " + location.toString());
                }

                jReader = Json.createReader(new InputStreamReader(urlConn.getInputStream()));
                JsonObject response = jReader.readObject();

                if (response.getBoolean("active")) {
                    String userName = response.getString("username", response.getString("sub", null));
                    if (userName != null) {
                        Subject result = new Subject();
                        result.getPrincipals().add(new OAuth2Principal(userName));
                        logger.info("User authenticated " + userName);
                        return result;
                    }
                }

            } catch (Exception ex) {

                logger.log(Level.SEVERE, ex.getMessage(), ex);

            } finally {

                if (dataStream != null) {
                    try {
                        dataStream.close();
                    } catch (Throwable th) {
                        logger.log(Level.SEVERE, th.getMessage(), th);
                    }
                }

                if (jReader != null) {
                    try {
                        jReader.close();
                    } catch (Throwable th) {
                        logger.log(Level.SEVERE, th.getMessage(), th);
                    }
                }

                if (urlConn != null)
                    urlConn.disconnect();
            }
        }

        throw new IdentityManagerException("User not authenticated");
    }

    public Subject authenticate()
        throws IdentityManagerException {

        HttpServletRequest request = AttributeAuthorityContext.getRequest();

        if (request == null) {
            throw new IdentityManagerException("Cannot retrieve current request");
        }

        /*
         * RFC 6750 2.1
         */
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            String[] strToks = authHeader.split(" ");
            if (strToks.length == 2 && strToks[0].equals("Bearer")) {
                return validateToken(strToks[1]);
            }
        }

        throw new IdentityManagerException("User not authenticated");
    }

    public void close()
        throws IdentityManagerException {

    }

    public class OAuth2Principal
        implements Principal {

        private String id;

        public OAuth2Principal(String uName) {
            id = uName;
        }

        public String getName() {
            return id;
        }
    }

}