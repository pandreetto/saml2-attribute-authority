package it.infn.security.saml.configuration;

import it.infn.security.saml.aa.CodedException;

public class ConfigurationException
    extends CodedException {

    public static final long serialVersionUID = 1432212959;

    public ConfigurationException(String msg, int code) {
        super(msg, code);
    }

    public ConfigurationException(String msg) {
        super(msg);
    }

    public ConfigurationException(String msg, int code, Throwable th) {
        super(msg, code, th);
    }

    public ConfigurationException(String msg, Throwable th) {
        super(msg, th);
    }

}