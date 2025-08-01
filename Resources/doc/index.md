Getting Started With FOSOAuthServerBundle
=========================================

## Prerequisites

This version of the bundle requires Symfony 7

#### Translations

If you wish to use default texts provided in this bundle, you have to make sure you have translator enabled in your config:

    # config/package/translations.yml

    framework:
        translator:
            fallbacks: 
                - 'en'

For more information about translations, check [Symfony documentation](http://symfony.com/doc/current/book/translation.html).


## Installation

Installation is a quick 5 steps process:

1. Download FOSOAuthServerBundle
2. Create your model class
3. Configure your application's security.yml
4. Configure the FOSOAuthServerBundle


### Step 1: Install FOSOAuthServerBundle

The preferred way to install this bundle is to rely on [Composer](http://getcomposer.org).
Just check on [Packagist](http://packagist.org/packages/klapaudius/oauth-server-bundle) the version you want to install (in the following example, we used "dev-master") and add it to your `composer.json`:

``` js
{
    "require": {
        // ...
        "klapaudius/oauth-server-bundle": "dev-master"
    }
}
```

### Step 2: Create model classes

This bundle needs to persist some classes to a database:

- `Client` (OAuth2 consumers)
- `AccessToken`
- `RefreshToken`
- `AuthCode`

Your first job, then, is to create these classes for your application.
These classes can look and act however you want: add any
properties or methods you find useful.

These classes have just a few requirements:

1. They must extend one of the base classes from the bundle
2. They must have an `id` field

In the following sections, you'll see examples of how your classes should
look, depending on how you're storing your data.

Your classes can live inside any bundle in your application. For example,
if you work at "Acme" company, then you might create a bundle called `AcmeApiBundle`
and place your classes in it.

**Warning:**

> If you override the __construct() method in your classes, be sure
> to call parent::__construct(), as the base class depends on
> this to initialize some fields.


#### Doctrine ORM classes

If you're persisting your data via the Doctrine ORM, then your classes
should live in the `Entity` namespace of your bundle and look like this to
start:

``` php
<?php
// src/Entity/Client.php

namespace App\Entity;

use FOS\OAuthServerBundle\Entity\Client as BaseClient;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 */
class Client extends BaseClient
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    public function __construct()
    {
        parent::__construct();
        // your own logic
    }
}
```

``` php
<?php
// src/Model/ClientManager.php

namespace App\Model;

use App\Entity\Client;
use App\Repository\ClientRepository;
use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;

class ClientManager implements ClientManagerInterface
{
    private ClientRepository $repository;

    public function __construct ( ClientRepository $repository )
    {
        $this->repository = $repository;
    }

    public function createClient(): ClientInterface
    {
        return new Client();
    }

    public function getClass(): string
    {
        return Client::class;
    }

    public function findClientBy( array $criteria ): ?ClientInterface
    {
        return $this->repository->findOneBy( $criteria );
    }

    public function findClientByPublicId( $publicId ): ?ClientInterface
    {
        return $this->repository->findOneBy([
                'publicId' => $publicId,
        ]);
    }

    public function updateClient( ClientInterface $client ): ClientInterface
    {
        /** @var Client $client */
        $this->repository->add( $client, true );

        return $client;
    }

    public function deleteClient( ClientInterface $client ): ClientInterface
    {
        /** @var Client $client */
        $this->repository->remove( $client, true );

        return $client;
    }
}


```

``` php
<?php
// src/App/Entity/AccessToken.php

namespace App\Entity;

use FOS\OAuthServerBundle\Entity\AccessToken as BaseAccessToken;
use Doctrine\ORM\Mapping as ORM;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 */
class AccessToken extends BaseAccessToken
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\ManyToOne(targetEntity="Client")
     * @ORM\JoinColumn(nullable=false)
     */
    protected ClientInterface $client;

    /**
     * @ORM\ManyToOne(targetEntity="Your\Own\Entity\User")
     * @ORM\JoinColumn(name="user_id", referencedColumnName="id", onDelete="CASCADE")
     */
    protected ?UserInterface $user = null;
}
```

``` php
<?php
// src/App/Entity/RefreshToken.php

namespace App\Entity;

use FOS\OAuthServerBundle\Entity\RefreshToken as BaseRefreshToken;
use Doctrine\ORM\Mapping as ORM;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 */
class RefreshToken extends BaseRefreshToken
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\ManyToOne(targetEntity="Client")
     * @ORM\JoinColumn(nullable=false)
     */
    protected ClientInterface $client;

    /**
     * @ORM\ManyToOne(targetEntity="Your\Own\Entity\User")
     * @ORM\JoinColumn(name="user_id", referencedColumnName="id", onDelete="CASCADE")
     */
    protected ?UserInterface $user = null;
}
```

``` php
<?php
// src/App/Entity/AuthCode.php

namespace App\Entity;

use FOS\OAuthServerBundle\Entity\AuthCode as BaseAuthCode;
use Doctrine\ORM\Mapping as ORM;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 */
class AuthCode extends BaseAuthCode
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\ManyToOne(targetEntity="Client")
     * @ORM\JoinColumn(nullable=false)
     */
    protected ClientInterface $client;

    /**
     * @ORM\ManyToOne(targetEntity="Your\Own\Entity\User")
     * @ORM\JoinColumn(name="user_id", referencedColumnName="id", onDelete="CASCADE")
     */
    protected ?UserInterface $user = null;
}
```

__Note__: If you don't have `auto_mapping` activated in your doctrine configuration you need to add
`FOSOAuthServerBundle` to your mappings in `config.yml`.

#### Doctrine ODM classes
``` php
<?php

// src/App/Document/Client.php

namespace App\Document;

use FOS\OAuthServerBundle\Document\Client as BaseClient;

class Client extends BaseClient
{
    protected $id;
}
```

``` xml
<!-- src/App/Resources/config/doctrine/Client.mongodb.xml -->

<doctrine-mongo-mapping xmlns="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping
                    http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping.xsd">

    <document name="App\Document\Client" db="acme" collection="oauthClient" customId="true">
        <field fieldName="id" id="true" strategy="AUTO" />
    </document>

</doctrine-mongo-mapping>
```

``` php
<?php

// src/App/Document/AuthCode.php

namespace App\Document;

use FOS\OAuthServerBundle\Document\AuthCode as BaseAuthCode;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AuthCode extends BaseAuthCode
{
    protected $id;
    protected ClientInterface $client;
    protected ?UserInterface $user = null;

    public function getClient(): ClientInterface
    {
        return $this->client;
    }

    public function setClient(ClientInterface $client): void
    {
        $this->client = $client;
    }

    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }
}
```

``` xml
<!-- src/App/Resources/config/doctrine/AuthCode.mongodb.xml -->

<doctrine-mongo-mapping xmlns="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping
                    http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping.xsd">

    <document name="App\Document\AuthCode" db="acme" collection="oauthAuthCode" customId="true">
        <field fieldName="id" id="true" strategy="AUTO" />
        <reference-one target-document="App\Document\Client" field="client" />
    </document>

</doctrine-mongo-mapping>
```

``` php
<?php

// src/App/Document/AccessToken.php

namespace App\Document;

use FOS\OAuthServerBundle\Document\AccessToken as BaseAccessToken;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AccessToken extends BaseAccessToken
{
    protected $id;
    protected ClientInterface $client;
    protected ?UserInterface $user = null;

    public function getClient()
    {
        return $this->client;
    }

    public function setClient(ClientInterface $client)
    {
        $this->client = $client;
    }

    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }
}
```

``` xml
<!-- src/App/Resources/config/doctrine/AccessToken.mongodb.xml -->

<doctrine-mongo-mapping xmlns="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping
                    http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping.xsd">

    <document name="App\Document\AccessToken" db="acme" collection="oauthAccessToken" customId="true">
        <field fieldName="id" id="true" strategy="AUTO" />
        <reference-one target-document="App\Document\Client" field="client" />
    </document>

</doctrine-mongo-mapping>
```

``` php
<?php

// src/App/Document/RefreshToken.php

namespace App\Document;

use FOS\OAuthServerBundle\Document\RefreshToken as BaseRefreshToken;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class RefreshToken extends BaseRefreshToken
{
    protected $id;
    protected ClientInterface $client;
    protected ?UserInterface $user = null;

    public function getClient()
    {
        return $this->client;
    }

    public function setClient(ClientInterface $client)
    {
        $this->client = $client;
    }

    public function getUser(): ?UserInterface
    {
        return $this->user;
    }

    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }
}
```

``` xml
<!-- src/App/Resources/config/doctrine/RefreshToken.mongodb.xml -->

<doctrine-mongo-mapping xmlns="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping
                    http://doctrine-project.org/schemas/odm/doctrine-mongo-mapping.xsd">

    <document name="App\Document\RefreshToken" db="acme" collection="oauthRefreshToken" customId="true">
        <field fieldName="id" id="true" strategy="AUTO" />
        <reference-one target-document="App\Document\Client" field="client" />
    </document>

</doctrine-mongo-mapping>
```

### Step 3: Configure your application's security.yml

In order for Symfony's security component to use the FOSOAuthServerBundle, you must
tell it to do so in the `security.yml` file. The `security.yml` file is where the
basic configuration for the security for your application is contained.

Below is a minimal example of the configuration necessary to use the FOSOAuthServerBundle
in your application:

``` yaml
# config/packages/security.yml
security:
    firewalls:
        oauth_token:
            pattern:    ^/oauth/v2/token
            security:   false
            methods:    [POST]

        oauth_authorize:
            pattern:    ^/oauth/v2/auth
            # Add your favorite authentication process here

        api:
            pattern:    ^/api
            fos_oauth:  true
            stateless:  true

    access_control:
        - { path: ^/api, roles: [ IS_AUTHENTICATED_FULLY ] }
```

The URLs under `/api` will use OAuth2 to authenticate clients.

#### Anonymous access

Sometimes you need to allow your api to be accessed without authorization. In order to do that lets adjust
above-mentioned example configuration.

``` yaml
# config/packages/security.yml
security:
    firewalls:
        oauth_token:
            pattern:    ^/oauth/v2/token
            security:   false
            methods:    [POST]

        oauth_authorize:
            pattern:    ^/oauth/v2/auth
            # Add your favorite authentication process here

        api:
            pattern:    ^/api
            fos_oauth:  true
            stateless:  true
            anonymous:  true # note that anonymous access is now enabled

    # also note absence of "access_control" section
```

From now on all of your api resources can be accessed without authorization. But what if one or more of them should be
secured anyway or/and require presence of authenticated user? It's easy! You can do that manually by adding few lines of
code at the beginning of all of your secured actions like in the example below:

``` php
// [...]
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class YourApiController extends Controller
{
    public function getSecureResourceAction()
    {
        # this is it
        if (false === $this->get('security.context')->isGranted('IS_AUTHENTICATED_FULLY')) {
            throw new AccessDeniedException();
        }

        // [...]
    }
```

### Step 4: Configure FOSOAuthServerBundle

Add references to the token.xml and the tuthorize.xml configuration files in config/routes/oauth2.yml:

``` yaml
# config/routes/oauth2.yml
fos_oauth_server_token:
    resource: "@FOSOAuthServerBundle/Resources/config/routing/token.xml"

fos_oauth_server_authorize:
    resource: "@FOSOAuthServerBundle/Resources/config/routing/authorize.xml"
```

Add FOSOAuthServerBundle settings in config/packages/fos_auth_server.yml:

``` yaml
# config/packages/fos_auth_server.yml
fos_oauth_server:
    db_driver: orm       # Drivers available: orm or mongodb
    client_class:        App\Entity\Client
    access_token_class:  App\Entity\AccessToken
    refresh_token_class: App\Entity\RefreshToken
    auth_code_class:     App\Entity\AuthCode
    
services:
    fos_oauth_server.client_manager:
        class: App\Model\ClientManager
        arguments:
            - '@App\Repository\ClientRepository'
```

If you're authenticating users, don't forget to set the user provider.
Here's an example using the FOSUserBundle user provider:

``` yaml
# config/packages/fos_auth_server.yml
fos_oauth_server:
    ...

    service:
        user_provider: fos_user.user_provider.username
        
services:
    fos_oauth_server.user_provider.default:
        class: App\Model\UserManager
        arguments:
            - '@App\Repository\UserRepository'
```

``` php
<?php

// src/Model/UserManager

namespace App\Model;

use App\Repository\UserRepository;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserManager implements UserProviderInterface
{
    private UserRepository $repository;

    public function __construct ( UserRepository $repository )
    {
        $this->repository = $repository;
    }

    public function refreshUser( UserInterface $user ) {
        return $user;
    }

    public function supportsClass( string $class ) {
        return true;
    }

    public function loadUserByIdentifier( string $identifier ): UserInterface {
        return $this->repository->findOneBy( ['username' => $identifier] );
    }

    public function loadUserByUsername( $username ) {
        return $this->repository->findOneBy( ['username' => $username] );
    }
}

```

## Creating A Client

### Console Command

The most convenient way to create a client is to use the console command.

    $ php app/console fos:oauth-server:create-client --redirect-uri="..." --grant-type="..."
    
Note: you can use `--redirect-uri` and `--grant-type` multiple times to add additional values.

### Programatically

Before you can generate tokens, you need to create a Client using the ClientManager.

``` php
$clientManager = $this->container->get('fos_oauth_server.client_manager.default');
$client = $clientManager->createClient();
$client->setRedirectUris(array('http://www.example.com'));
$client->setAllowedGrantTypes(array('token', 'authorization_code'));
$clientManager->updateClient($client);
```

Once you have created a client, you need to pass its `publicId` to the authorize endpoint. You also need
to specify a redirect uri as well as a response type.

```php
return $this->redirect($this->generateUrl('fos_oauth_server_authorize', array(
    'client_id'     => $client->getPublicId(),
    'redirect_uri'  => 'http://www.example.com',
    'response_type' => 'code'
)));
```

## Usage

The `token` endpoint is at `/oauth/v2/token` by default (see `Resources/config/routing/token.xml`).

The `authorize` endpoint is at `/oauth/v2/auth` by default (see `Resources/config/routing/authorize.xml`).


## Next steps

[A Note About Security](a_note_about_security.md)

[Configuration Reference](configuration_reference.md)

[Dealing With Scopes](dealing_with_scopes.md)

[Extending the Authorization page](extending_the_authorization_page.md)

[Extending the Model](extending_the_model.md)

[The OAuthEvent class](the_oauth_event_class.md)

[Adding Grant Extensions](adding_grant_extensions.md)

[Custom DB Driver](custom_db_driver.md)
