package it.infn.security.saml.ocp.emulators;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import it.infn.security.saml.aa.CodedException;
import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.iam.impl.SimpleAccessManager;

public class AgidEmulator
    extends HttpServlet {

    private static final long serialVersionUID = 1461918744;

    private static final Logger logger = Logger.getLogger(AgidEmulator.class.getName());

    private static final String AGID_EMUL_CONFFILE = "agid.emulator.configuration.file";

    private static final String QUIET_TIME = "agid.emulator.refresh.quite.time";

    private static final String REGISTRY_PROPERTY = "providers";

    private static final String ENTITY_PROPERTY = "entityId";

    private static final String URL_PROPERTY = "url";

    private static final String AGID_EMUL_DEFFILE = "/etc/saml2-attribute-authority/emulator.json";

    private HashMap<String, String> registry;

    private File registryFile;

    private long lastModACL;

    private long tick;

    private long quiteTime;

    @Override
    public void init(ServletConfig config)
        throws ServletException {

        super.init(config);

        registry = new HashMap<String, String>();
        lastModACL = 0;
        tick = System.currentTimeMillis();

        try {

            AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

            registryFile = new File(configuration.getMetadataSourceParam(AGID_EMUL_CONFFILE, AGID_EMUL_DEFFILE));
            quiteTime = configuration.getAccessManagerParamAsInt(QUIET_TIME, 5000);

            loadRegistry();

            logger.info("AGID registry emulator at " + configuration.getAuthorityURL() + "/registry");

        } catch (CodedException cEx) {
            logger.log(Level.SEVERE, cEx.getMessage(), cEx);
            throw new ServletException("Cannot configure AGID emulator");
        }

    }

    @Override
    public void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
        throws ServletException, IOException {

        @SuppressWarnings("unchecked")
        Map<String, String[]> reqParams = httpRequest.getParameterMap();

        if (!reqParams.containsKey("entityId")) {

            logger.severe("Undefined entityId in requet");
            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;

        }

        String entityId = reqParams.get("entityId")[0];
        logger.info("Query registry for " + entityId);

        if (registry.containsKey(entityId)) {

            StringBuffer tmpbuf = new StringBuffer("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            tmpbuf.append("<agidns:FederationRegistry xmlns:agidns=\"http://www.agid.gov.it/spid\" ");
            tmpbuf.append("targetNamespace=\"http://www.agid.gov.it/spid\">");
            tmpbuf.append("<agidns:AuthorityInfo><agidns:MetadataProviderURL>");

            tmpbuf.append(getEntityURL(entityId));

            tmpbuf.append("</agidns:MetadataProviderURL></agidns:AuthorityInfo>");
            tmpbuf.append("</agidns:FederationRegistry>");

            httpResponse.setStatus(HttpServletResponse.SC_OK);
            httpResponse.setContentType("text/html;charset=UTF-8");

            Writer writer = httpResponse.getWriter();
            writer.write(tmpbuf.toString());
            httpResponse.flushBuffer();

        } else {

            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);

        }

    }

    private void loadRegistry()
        throws ServletException {

        JsonReader jReader = null;
        registry.clear();

        try {
            if (!registryFile.canRead()) {
                logger.warning("Cannot read " + registryFile.getAbsolutePath() + "; disabled publication");
                return;
            }

            jReader = Json.createReader(new FileReader(registryFile));
            JsonObject rootObj = jReader.readObject();

            JsonArray tmpArray = rootObj.getJsonArray(REGISTRY_PROPERTY);
            if (tmpArray != null) {
                for (JsonValue jValue : tmpArray) {
                    JsonObject entDict = (JsonObject) jValue;
                    String entityId = entDict.getJsonString(ENTITY_PROPERTY).getString();
                    String url = entDict.getJsonString(URL_PROPERTY).getString();
                    logger.info("Loaded entityId " + entityId + " - " + url);
                    registry.put(entityId, url);
                }
            }

        } catch (Exception ex) {

            logger.log(Level.SEVERE, ex.getMessage(), ex);
            throw new ServletException("Cannot load registry");

        } finally {
            if (jReader != null)
                try {
                    jReader.close();
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, ex.getMessage(), ex);
                }
        }

    }

    private String getEntityURL(String entId)
        throws ServletException {

        long now = System.currentTimeMillis();
        if ((now - tick) > quiteTime) {
            if (registryFile.lastModified() != lastModACL) {
                synchronized (SimpleAccessManager.class) {
                    if (registryFile.lastModified() != lastModACL) {
                        tick = now;
                        loadRegistry();
                        lastModACL = registryFile.lastModified();
                        logger.info("Reloaded registry file: " + registryFile.getAbsolutePath());
                    }
                }
            }
        }

        return registry.get(entId);
    }

}
