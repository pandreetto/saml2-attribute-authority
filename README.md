# SAML2 Attribute Authority


## Build with Maven

Requirements:

- Java 7
- Maven 3

Build it with the following command:

  mvn install
  
the web-application file is target/saml2-attribute-authority-*.*.war

## Eclipse import instructions

To import the project in Eclipse for development, do as follows:

  mvn clean eclipse:clean
  mvn eclipse:eclipse

From Eclipse menu, select “Import Existing Maven projects...”, and
point it to this project root directory.

## Build and deploy artifact on tomcat7

Requirements:

- the tomcat admin web-application
- mysql server


Tomcat configuration:

Define the following declarations in the tomcat admin configuration file (/etc/tomcat/tomcat-users.xml):
```
<tomcat-users>
  <role rolename="admin"/>
  <role rolename="admin-gui"/>
  <role rolename="admin-script"/>
  <role rolename="manager"/>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="manager-jmx"/>
  <role rolename="manager-status"/>
  <user name="admin" password="***********" 
        roles="admin,manager,admin-gui,admin-script,manager-gui,manager-script,manager-jmx,manager-status" />
</tomcat-users>

```

Maven configuration:

In the maven per-user configuration file ($HOME/.m2/settings.xml) define the following properties:
```
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <profiles>
    <profile>
      <id>tomcatenabled-profile</id>
      <activation><activeByDefault>true</activeByDefault></activation>
        <properties>
          <tomcat.manager.type>tomcat7</tomcat.manager.type>
          <tomcat.manager.epr>http://***************:****/manager/text</tomcat.manager.epr>
          <tomcat.manager.login>tomcatloginid</tomcat.manager.login>
        </properties>
    </profile>
  </profiles>
  
  <servers>
    <server>
      <id>tomcatloginid</id>
      <username>admin</username>
      <password>***********</password>
    </server>
  </servers>
  
</settings>
```
The property *tomcat.manager.epr* contains the url of tomcat installation.
The tags *username* and *password* refer to the administrator account configured in tomcat, as described above.

Deployment:

  mvn clean tomcat7:deploy

Configuration of the web application:

For a single context installation the default configuration file is */etc/saml2-attribute-authority/configuration.conf*.
The file is a simple java property file (key = value) with the following definitions:

  Generale definitions:
- authority.id : the SAML2 id of the service
- authority.id.format : the format of the SAML2 id
- authority.url : the endpoint of the query attribute service

  Credential definitions:
- key.manager.file : the keystore file containing the server credentials
- key.manager.type : the type of the keystore file (JKS, PKCS12)
- key.manager.password : the password of the keystore file
- key.manager.alias : the alias of the credential to use inside the keystore file
- trust.manager.file : the truststore file containing the CA certificates
- trust.manager.type : the type of the truststore file (JKS, PKCS12)
- trust.manager.password : 

  Metadata definitions:
- metadata.expiration_time : the expiration time of the published metadata
- organization.name.<lang> : the localized name of the organization running the service
- organization.displayname.<lang> : the localized human readable name of the organization
- organization.url.<lang> : the localized url of the organization site
- contact.type.<contactid> : the type of the contact for a given contactid (administrative, billing, support, technical, other)
- contact.givenName.<contactid> : the given name for a given contactid
- contact.surName.<contactid> : the family name a given contactid
- contact.emails.<contactid> : a comma separated list of email addresses a given contactid
- contact.phones.<contactid> : a comma separated list of phone numbers a given contactid

  Datasource definitions (hibernate implementation):
The set of properties are the ones required by hibernate (http://docs.jboss.org/hibernate/orm/4.3/manual/en-US/html/ch03.html)

This is an example of a configuration file:
```
authority.id=saml2aa.infn.it:8443:it.infn.security.saml
authority.id.format=urn:oasis:names:tc:SAML:2.0:nameid-format:entity
authority.url=https://saml2aa.infn.it:8443/saml2-attribute-authority
key.manager.file=/etc/tomcat/hostkeys.p12
key.manager.type=PKCS12
key.manager.password=myp@ssw0rd
key.manager.alias=tomcat
trust.manager.file=/etc/tomcat/mytruststore.jks
trust.manager.type=JKS
trust.manager.password=myp@ssw0rd
metadata.expiration_time=432000

hibernate.connection.driver_class=org.gjt.mm.mysql.Driver
hibernate.connection.url=jdbc:mysql://saml2aa.infn.it:3306/db?autoReconnect=true
hibernate.connection.username=mbuto
hibernate.connection.password=myp@ssw0rd
hibernate.dialect=org.hibernate.dialect.MySQL5InnoDBDialect

hibernate.c3p0.min_size=5
hibernate.c3p0.max_size=20
hibernate.c3p0.timeout=60
hibernate.c3p0.max_statements=50
hibernate.c3p0.idle_test_period=3000

hibernate.current_session_context_class=thread
hibernate.cache.provider_class=org.hibernate.cache.internal.NoCacheProvider
hibernate.show_sql=true
hibernate.hbm2ddl.auto=update

contact.type.id01=support
contact.givenName.id01=Mario
contact.surName.id01=Rossi
contact.emails.id01=mario.rossi@example.it,rossim@example.com
contact.phones.id01=3456859386,340797234107

contact.type.id02=technical
contact.givenName.id02=Guido
contact.surName.id02=Bianchi
contact.emails.id02=guido.bianchi@example.net
contact.phones.id02=3354254523,352452345423

organization.name.en=INFN
organization.displayname.en=National Institute for Nuclear Physics
organization.url.en=http://www.infn.it

```







