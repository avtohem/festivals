[![Build Status](https://travis-ci.org/donalmurtagh/festivals.svg?branch=master)](https://travis-ci.org/donalmurtagh/festivals)

## Festivals
Testing
A [responsive Grails website](https://web.archive.org/web/20150803152205/http://www.festivals.ie/) that provides information about festivals in Ireland and beyond. Features of
the application include:

* **Calendars** that shows festivals by time
* **Maps** that show festivals by location
* **Artist Alerts** - registered users can subscribe to an artist and will receive an email when that artist is added to
a festival's lineup
* **Festival Alerts** - registered users can subscribe to a festival and will receive an email when that festival's lineup
changes
* Registered users can **rate and review festivals**
* **Reminders** - registered users can request to receive a reminder about a festival by email up to 10 days before it starts
* **Blog**
* **Competitions**
* **Web Service** - a REST API allows festival data to be retrieved by location, time, festival type, etc 
* **CMS pages** allows administrators to add/remove/update artists, festivals, competitions, users, etc. Regular users can also
add festivals to the application, but they will not appear until approved by an administrator.
* In addition to artist and festival data entered manually by users, **content is automatically imported from online sources**
such as last.fm, Skiddle, Eventbrite, Muzu

## Run Locally
If you wish to run the application locally, you must have access to a MySQL server and [the 
relevant Grails version](https://github.com/domurtag/festivals/blob/master/application.properties) installed.

### Secret Configuration
After cloning this repository, a config file containing confidential parameters should be added to the 
[conf](https://github.com/domurtag/festivals/tree/master/grails-app/conf) directory, before the application is built.
The name of this file must be `secret.properties`. You can provide environment-specific overrides for these settings by
adding an additional configuration file named after the environment. For example, to override some/all of the settings in `secret.properties` for
the production environment, add the overrides to a file named `secret-PRODUCTION.properties` in the same directory. 

The contents of the secret configuration file(s) are described in the following subsections

#### Mandatory Secret Configuration

The application will fail to start unless these settings are added to the secret configuration file (or [DataSource.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/DataSource.groovy)).

````
dataSource.username=festival
dataSource.password=changeme
````

Additionally, a salt must be defined that is used when hashing passwords. Any reasonably long unguessable string will suffice
```
systemWidePasswordSalt=z{$c.?R;]SHFUYg?ZL>>.c!,K-8V<][]
```

#### Recommended Secret Configuration

If these settings are omitted, the application will start, but certain features will not work correctly. The consequences
of omitting each one and (where applicable) how to remove the feature completely are described below

##### Google Maps API Keys

These API keys are used when calling Google Maps APIs on the server and client side.
The hosts/IP addresses on which these keys can be used are [configured here](https://code.google.com/apis/console). 

````
festival.googleApiServerKey=changeme
festival.googleApiClientKey=changeme
````

##### Skiddle API Key

A daily job automatically imports festival data into the database from the [Skiddle events API](http://www.skiddle.com/api/).
This job will fail unless the key below is provided.

````
festival.skiddle.tag=changeme
````

To disable this feature, simply remove the relevant [Quartz class](https://github.com/domurtag/festivals/blob/master/grails-app/jobs/ie/festivals/job/ImportSkiddleFeedJob.groovy).

##### Eventbrite API Key

A daily job automatically imports festival data into the database from the [Eventbrite web service](http://developer.eventbrite.com).
This job will fail unless the key below is provided.

````
festival.eventbrite.accessToken=changeme
````

To disable this feature, simply remove the relevant [Quartz class](https://github.com/domurtag/festivals/blob/master/grails-app/jobs/ie/festivals/job/ImportEventbriteFestivalsJob.groovy).

##### Muzu API Key

Artist videos are retrieved from [Muzu's Data API](http://www.muzu.tv/api/). 

````
festival.muzuApiKey=changeme
````

To disable this feature, remove the [artist video service](https://github.com/domurtag/festivals/blob/master/grails-app/services/ie/festivals/ArtistVideoService.groovy) 
and all references to it.

##### Last.fm API Key

To retrieve artist data and images from the [Last.fm API](http://www.last.fm/api) you will need to add the following:

````
festival.lastFM.apiKey=changeme
````

##### Booking.com

To earn commission when users are successfully referred to http://booking.com, add the following:
 
````
festivals.bookingDotComAffiliateId=changeme
````
 
##### Mail Server Password
 
Configure the password for the SMTP account that the application uses to send email
 
````
grails.mail.password=changeme
````

To disable email sending, set `festival.sendEmail = false` in [Config.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/Config.groovy)

##### OAuth2

OAuth2 is used to allow users to register and login to the application using services such as Facebook, Twitter, 
Google+, etc. For each provider that you wish to support, a key (AKA a client ID) and a secret must be added

````
oauth.${provider}.key=provider-clientId
oauth.${provider}.secret=provider-secret
````

For example, to support the Facebook OAuth2 provider, add the following

````
oauth.facebook.key=my-facebook-oauth-clientId
oauth.facebook.secret=my-facebook-oauth-secret
````

##### Airbrake API Key

Errors that occur within the application are recorded by [Airbake](https://airbrake.io/). To use this service, you must
add the following configuration

````
grails.plugins.airbrake.apiKey=changeme
````

To disable Airbrake, simply uninstall the [Grails Airbrake plugin](https://github.com/domurtag/festivals/blob/master/grails-app/conf/BuildConfig.groovy).

##### Password Salt

When users register, their password is salted and hashed before being persisted. Set the password salt to a random string
via the setting below

````
systemWidePasswordSalt=choose-any-random-string-but-dont-ever-change-it
````

### Database Configuration

When the application is run in the development environment, it is assumed that the MySQL server is running on localhost,
and the name of the schema is "festival". To change these defaults update `dataSource.url` in [DataSource.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/DataSource.groovy).

The database tables will be automatically created by the application on startup, but the schema itself
must already exist beforehand. Run `show databases` from the MySQL console to verify the existence of a schema with
the correct name.

To fully support the most esoteric Unicode characters, MySQL should be changed to [use utf8mb4 encoding](https://mathiasbynens.be/notes/mysql-utf8mb4) 
by adding the following to the MySQL configuration file

````
[client]
default-character-set = utf8mb4

[mysql]
default-character-set = utf8mb4

[mysqld]
character-set-client-handshake = FALSE
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
````

However in most cases, this step can be skipped as the default utf8 encoding should suffice.

### Local Filesystem Access

The application requires access to the local filesystem in order to

* Store the index created by the [Searchable plugin](http://grails.org/plugin/searchable). The location where this is
stored is controlled by the `compassConnection` setting in [Searchable.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/Searchable.groovy)

* Store images when a new artist is added with a custom image. The location where these images
are saved is controller by the `festival.images.artistDir` setting in [Config.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/Config.groovy)

### Launch Application

Once the steps described above have been followed the application can be started (in development mode) 
by running `grails run-app` on the command-line from the application's root directory. 

The application requires a heap size of about 1 gigabyte to *run*, but it requires more than this to *build* because the 
optimizations applied to the front-end resources consume a lot of memory. Therefore, before running a Grails command that 
invokes the build (e.g. `grails war` or `grails run-app`) it is recommended that you set the initial/max heap size to
at least 600/1200 megabytes.

Commands that run in the development environment will automatically choose the appropriate memory settings on account of
the `grails.project.fork` [configuration](https://github.com/domurtag/festivals/blob/master/grails-app/conf/BuildConfig.groovy).
In other environments, the memory settings can be applied by setting the `GRAILS_OPTS` environment variable, e.g.
`export GRAILS_OPTS="-Xms600m -Xmx1200m"`

By default the following users will automatically be created on startup:

| Username                       | Password | Role          |
| ------------------------------ | ---------| ------------- |
| festival-admin@mailinator.com  | password | Administrator |
| festival-user@mailinator.com   | password | User          |

These defaults can be changed in [BootStrap.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/BootStrap.groovy)

## Automated Tests

Before running the integration tests for the first time an empty MySQL schema named "festival_test" must be created 
on localhost. By default, the tests access this schema with username "root" and a blank password. The default test database
settings can be changed in [DataSource.groovy](https://github.com/domurtag/festivals/blob/master/grails-app/conf/DataSource.groovy).

Once the schema has been created, the unit and integration tests can be executed by running `grails test-app` on the 
command-line from the application's root directory.

## License

This application is made available under the Apache 2 license. It includes a copy of the [Highcharts](http://www.highcharts.com/) 
and [Isotope](https://github.com/metafizzy/isotope) libraries, which are *not* free for commercial purposes, so if you wish to 
use this application for commercial purposes you must either remove these libraries, or purchase a commercial license for them. 
All other third-party software included in this application may be used free-of-charge for both commercial and non-commercial purposes.
