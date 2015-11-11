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
  <user name="admin" password="***********" roles="admin,manager,admin-gui,admin-script,manager-gui,manager-script,manager-jmx,manager-status" />
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
The property *tomcat.manager.epr* contains the url of tomcat installation
The tags username and password refer to the administrator account configured in tomcat, as described above.

Deployment:

  mvn clean tomcat7:deploy



