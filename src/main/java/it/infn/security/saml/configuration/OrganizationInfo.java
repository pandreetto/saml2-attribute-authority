package it.infn.security.saml.configuration;

import it.infn.security.saml.utils.SAML2ObjectBuilder;

import java.util.HashMap;

import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;

public class OrganizationInfo {

    private HashMap<String, String> nameTable;

    private HashMap<String, String> displayNameTable;

    private HashMap<String, String> urlTable;

    public OrganizationInfo() {

        nameTable = new HashMap<String, String>();
        displayNameTable = new HashMap<String, String>();
        urlTable = new HashMap<String, String>();

    }

    public void setName(String name, String lang) {
        if (name == null || name.length() == 0) {
            return;
        }
        if (lang == null || lang.length() == 0) {
            lang = "en";
        }
        nameTable.put(name, lang);
    }

    public void setDisplayName(String dName, String lang) {
        if (dName == null || dName.length() == 0) {
            return;
        }
        if (lang == null || lang.length() == 0) {
            lang = "en";
        }
        displayNameTable.put(dName, lang);
    }

    public void setURL(String url, String lang) {
        if (url == null || url.length() == 0) {
            return;
        }
        if (lang == null || lang.length() == 0) {
            lang = "en";
        }
        urlTable.put(url, lang);
    }

    public Organization buildOrganization() {

        if (nameTable.size() == 0) {
            return null;
        }

        Organization result = SAML2ObjectBuilder.buildOrganization();

        for (String key : nameTable.keySet()) {
            OrganizationName orgName = SAML2ObjectBuilder.buildOrganizationName();
            orgName.setName(new LocalizedString(key, nameTable.get(key)));
            result.getOrganizationNames().add(orgName);
        }

        for (String key : displayNameTable.keySet()) {
            OrganizationDisplayName dispName = SAML2ObjectBuilder.buildOrganizationDisplayName();
            dispName.setName(new LocalizedString(key, displayNameTable.get(key)));
            result.getDisplayNames().add(dispName);
        }

        for (String key : urlTable.keySet()) {
            OrganizationURL orgUrl = SAML2ObjectBuilder.buildOrganizationURL();
            orgUrl.setURL(new LocalizedString(key, urlTable.get(key)));
            result.getURLs().add(orgUrl);
        }

        return result;
    }

}