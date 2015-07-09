package it.infn.security.saml.handler;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;

public class SAML2HandlerFactory {

    private static SAML2Handler handler = null;

    public static SAML2Handler getHandler()
        throws SAML2HandlerException {

        if (handler == null) {

            synchronized (SAML2HandlerFactory.class) {

                if (handler == null) {

                    try {

                        AuthorityConfiguration config = AuthorityConfigurationFactory.getConfiguration();

                        Class<?> cls = Class.forName(config.getSAMLsHandlerClass());
                        handler = (SAML2Handler) cls.newInstance();

                    } catch (Exception ex) {
                        throw new SAML2HandlerException("Cannot load saml handler", ex);
                    }

                }

            }

        }

        return handler;

    }

}