package it.infn.security.saml.configuration;

public class ConfigurationException
    extends Exception {

    public static final long serialVersionUID = 1432212959;

    public ConfigurationException() {
        super();
    }

    public ConfigurationException(String msg) {
        super(msg);
    }

    public ConfigurationException(String msg, Throwable th) {
        super(msg, th);
    }

}