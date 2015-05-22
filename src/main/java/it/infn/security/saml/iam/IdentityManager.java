package it.infn.security.saml.iam;

public interface IdentityManager {
    
    public void init() throws IdentityManagerException;
    
    public void authenticate() throws IdentityManagerException;
    
    public void close() throws IdentityManagerException;
    
}