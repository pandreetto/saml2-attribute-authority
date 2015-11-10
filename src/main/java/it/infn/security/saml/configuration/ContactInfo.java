package it.infn.security.saml.configuration;

import it.infn.security.saml.utils.SAML2ObjectBuilder;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;

public class ContactInfo {

    private static final int ADMIN_TYPE = 4;

    private static final int BILL_TYPE = 3;

    private static final int SUPP_TYPE = 2;

    private static final int TECH_TYPE = 1;

    private static final int OTH_TYPE = 0;

    private int type;

    private String givenName;

    private String surName;

    private List<String> emails;

    private List<String> phones;

    public ContactInfo() {

        type = OTH_TYPE;
        givenName = null;
        surName = null;
        emails = new ArrayList<String>();
        phones = new ArrayList<String>();
    }

    public void setType(String typeStr) {

        if ("administrative".equalsIgnoreCase(typeStr)) {
            type = ADMIN_TYPE;
        } else if ("billing".equalsIgnoreCase(typeStr)) {
            type = BILL_TYPE;
        } else if ("support".equalsIgnoreCase(typeStr)) {
            type = SUPP_TYPE;
        } else if ("technical".equalsIgnoreCase(typeStr)) {
            type = TECH_TYPE;
        }
    }

    public void setGivenName(String gName) {
        givenName = gName;
    }

    public void setSurName(String sName) {
        surName = sName;
    }

    public void addEmail(String email) {
        if (email != null && email.length() > 0) {
            emails.add(email);
        }
    }

    public void addPhone(String phone) {
        if (phone != null && phone.length() > 0) {
            phones.add(phone);
        }
    }

    public ContactPerson buildContactPerson() {

        ContactPerson contact = SAML2ObjectBuilder.buildContactPerson();

        switch (type) {
        case ADMIN_TYPE:
            contact.setType(ContactPersonTypeEnumeration.ADMINISTRATIVE);
            break;
        case BILL_TYPE:
            contact.setType(ContactPersonTypeEnumeration.BILLING);
            break;
        case SUPP_TYPE:
            contact.setType(ContactPersonTypeEnumeration.SUPPORT);
            break;
        case TECH_TYPE:
            contact.setType(ContactPersonTypeEnumeration.TECHNICAL);
            break;
        default:
            contact.setType(ContactPersonTypeEnumeration.OTHER);
        }

        if (givenName != null) {
            GivenName gName = SAML2ObjectBuilder.buildGivenName();
            gName.setName(givenName);
            contact.setGivenName(gName);
        }

        if (surName != null) {
            SurName sName = SAML2ObjectBuilder.buildSurName();
            sName.setName(surName);
            contact.setSurName(sName);
        }

        for (String emailStr : emails) {
            EmailAddress email = SAML2ObjectBuilder.buildEmailAddress();
            email.setAddress(emailStr);
            contact.getEmailAddresses().add(email);
        }
        
        for(String phoneStr : phones) {
            TelephoneNumber phone = SAML2ObjectBuilder.buildTelephoneNumber();
            phone.setNumber(phoneStr);
            contact.getTelephoneNumbers().add(phone);
        }

        return contact;
    }
}