package it.infn.security.saml.handler;


public class SAML2HandlerFactory {

    private static SAML2Handler handler = null;

    public static SAML2Handler getHandler()
        throws SAML2HandlerException {

        if (handler == null) {

            synchronized (SAML2HandlerFactory.class) {

                if (handler == null) {

                    try {

                        int maxPriority = -1;
                        for (SAML2Handler tmphdlr : SAML2Handler.handlerLoader) {
                            if (tmphdlr.getLoadPriority() > maxPriority) {
                                maxPriority = tmphdlr.getLoadPriority();
                                handler = tmphdlr;
                            }
                        }

                    } catch (Exception ex) {
                        throw new SAML2HandlerException("Cannot load saml handler", ex);
                    }

                    if (handler == null) {
                        throw new SAML2HandlerException("Cannot find saml handler");
                    }

                }

            }

        }

        return handler;

    }

}