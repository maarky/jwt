PHP JWT
=======

A JSON Web Token, or JWT (pronounced "jot"), is a means of authentication. It allows a requester to create their own
authentication token that can be validated by the recipient. For details go [here](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

About JWTs
----------

In short, a JWT consists of three parts: a header, a claimset and a signature. The header and claimset are base64
encoded JSON objects and the signature is a base64 encoded hash of the header and claimset. These parts are concatenated
together separated by a period.

The header must contain a type (typ) and the hashing algorithm (algo) used to create the signature. You are allowed to
provide additional headers but these are the only two that are required.

Consider the following JWT:

    Header: {"alg":"HS256","typ":"JWT"}
    Claims: {"a":"claim A","b":"claim B","c":"claim C"}
    
    Base64 encoding the header and claims produces the following:
    
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMifQ
    ^----------------------------------^ ^--------------------------------------------------------^
     Header                               Claims
     
     Hashing the above using the HS256 hashing algorithm using the key "secret" provides the following base64 encoded signature:
     bkg61YGDQRi8mHk5ZtyEk0VEflEp5ZMfg71WQsEOaQE
     
     Put it all together and you get the following JWT:
    
    
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMifQ.bkg61YGDQRi8mHk5ZtyEk0VEflEp5ZMfg71WQsEOaQE
    ^----------------------------------^ ^--------------------------------------------------------^ ^-----------------------------------------^
     Header                               Claims                                                     Signature

Supported Validation
--------------------

This implementation checks that a valid type and algorithm are provided. It also validates the following public claims:

* Expiration (exp)
* Not Before (nbf)
* Issued At (iat)

Supported Hashing Algorithms
----------------------------

This implementation supports the following hashing algorithms:

* HS256
* HS384
* HS512

Requirements
============

This library requires PHP 7. Since many people may not yet be working with PHP 7 this library includes a Vagrantfile with
provisioning that installs php7.0-cli and Xdebug. It will also install Composer and PHPUnit. You can use this to run the 
unit tests and as a sandbox.

Options
-------

It also uses my Option library. Documentation on options can be found [here](https://github.com/maarky/option).

Installation
============

To install simply use composer:

    composer require maarky/jwt

Documentation
=============

Basics
------

There are two reasons for creating a Jwt object.

1. To create a token to authenticate with another service.
1. To validate a token provided by somebody trying to access your service.

You can create a token in the following way:

    use maarky\Jwt\Jwt;
    
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    $claims = [
        'a' => 'claim A',
        'b' => 'claim B',
        'c' => 'claim C'
    ];
    
    $jwt = new Jwt(['claims' => $claims, 'header' => $header], 'secret');
    echo $jwt->encode();
    
    //or
    
    $jwt = new Jwt(['claims' => $claims], 'secret');
    $jwt->setAlgo('HS256');
    echo $jwt->encode();
    
    //the following JWT will be echoed:
    //eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMifQ.bkg61YGDQRi8mHk5ZtyEk0VEflEp5ZMfg71WQsEOaQE

In the above example we provide the header and claims in an array and the secret is provided as a string. In the second
example above we do not provide a header. Instead, we provide the algorithm to the setAlgo() method. This adds it to the
header. Since there is only one valid value for the type it is added automatically when encoding if it has not already
been supplied.

If your service receives that JWT you can validate it like so:

    use maarky\Jwt\Jwt;
    
    $encodedJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMifQ.bkg61YGDQRi8mHk5ZtyEk0VEflEp5ZMfg71WQsEOaQE';
    $jwt = new Jwt($encodedJwt, 'secret');
    $jwt->isValid(); //true
    
    $jwt = new Jwt($encodedJwt, 'bad secret');
    $jwt->isValid(); //false because the wrong secret was used

In this example we create a Jwt object by providing a complete JWT and the secret. When validating the JWT we are
basically checking that the header and claims will produce the same signature given the provided secret.

Creating a Jwt Object
---------------------

You have a couple of options when instantiating the Jwt class.

If the first argument is a string it must be a JWT.

If the first argument is an array it may contain the following keys: claims, header and algo.

* claims: an array of claims
* header: an array of headers
* algo: a string equal to "HS256", "HS384" or "HS512"

If your header array contains an "alg" key you must not supply an algo.

The second argument is where you provide the secret. The secret must be a string or a callback function. If a callback
is provided it will be passed the Jwt object and must return a string. If the secret is a callback it will be called
when calling the getSecret() method. This method is only called internally when encoding the Jwt object and when
validating the object so a secret must be provided before either of those occur. 

You can also create an empty Jwt object:

    $jwt = new maarky\Jwt\Jwt();

Jwt Methods
-----------

The Jwt class has methods for adding and retrieving claims, headers and the secret and for encoding and validating the
Jwt object.

###Header Methods

####addHeader(string $header, $value)

Provide the header key and a value.

    $jwt->addHeader('header_key', 'header value');

####addHeaders(array $headers)

Use this method if you have an array of headers that you want to provide all at once.

    $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    
    $jwt->addHeaders($headers);

####getHeader(string $header): Option

Retrieve a specific header. Returns a Some if the header is found, otherwise a None.  
Documentation on Some and None can be found [here](https://github.com/maarky/option).

    $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    
    $jwt->addHeaders($headers);
    $jwt->getHeader('typ'); //returns Some('JWT')
    $jwt->getHeader('typo'); //returns None
    
    //determining if a header exists
    $jwt->getHeader('typ')->isDefined(); // returns true
    $jwt->getHeader('typ')->isEmpty(); // returns false
    $jwt->getHeader('typo')->isDefined(); // returns false
    $jwt->getHeader('typo')->isEmpty(); // returns true

####getHeaders(): ArrayOption

Retrieve all headers as an array Option. Documentation on Some and None can be found [here](https://github.com/maarky/option).

    use maarky\Jwt\Jwt;
    
    $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    $jwt = new Jwt($headers);
    $jwt->getHeaders(); //returns Some(['typ' => 'JWT', 'alt' => 'HS256'])

####getAllHeaders(): array

Retrieve all headers including the typ header, even if it hasn't been set.

    use maarky\Jwt\Jwt;
        
    $jwt = new Jwt();
    $jwt->getAllHeaders(); //returns ['typ' => 'JWT']
    
    $jwt = new Jwt(['header' => ['alg' => 'HS256']]);
    $jwt->getAllHeaders(); //returns ['alg' => 'HS256', 'typ' => 'JWT']
    
####removeHeader(string $header)

If you want to remove a header call this method and provide the key for the header you want to remove.

    use maarky\Jwt\Jwt;
    
    $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    $jwt = new Jwt(['header' => $headers]);
    $jwt->removeHeader('alg');
    $jwt->getHeaders(); //returns Some(['typ' => 'JWT'])

###Claims Methods

####addClaim(string $claim, $value)  
####addClaims(array $claim)  
####getClaim(string $claim): Option  
####getClaims(): ArrayOption  
####removeClaim(string $claim)

These methods work exactly like the respective header methods.

    use maarky\Jwt\Jwt;
        
    $jwt = new Jwt();
    $jwt->getClaims(); //returns array None
    
    $jwt->addClaim('claim1', 'value 1');
    $jwt->getClaim('claim1'); // returns Some('value 1')
    
    $jwt->addClaims(['claim2' => 'value 2', 'claim3' => 'value 3']);
    $jwt->getClaims(); //returns array Some(['claim1' => 'value 1', 'claim2' => 'value 2', 'claim3' => 'value 3']);
    
    $jwt->removeClaim('claim1');
    $jwt->getClaim('claim1'); // returns None
    $jwt->getClaims(); //returns array Some(['claim2' => 'value 2', 'claim3' => 'value 3']);

###Secret Methods

####setSecret($secret)

When setting a secret you can provide a string or a callback function. If a callback is provided it will be passed the
Jwt object and must return a string. If the secret is a callback it will be called when calling the getSecret() method.
This method is only called internally when encoding the Jwt object and when validating the object so a secret must be
provided before either of those occur.

Providing a callback can be useful if you need something from the claims in order to retrieve the secret. For example:

    use maarky\Jwt\Jwt;
    
    $providedJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMiLCJwdWJrIjoiams0NTM0a2pia2o0NSJ9.EZqOXe1dizNCK3zlSTDV54KflwJx2MZg6qdvSLr7Q_0';
    $findSecret = function(Jwt $jwt) use($repository) {
        return $jwt->getClaim('pubk')
                   ->map(function($value) { return $repository->findSecret($value); })
                   ->getOrElse('');
    };
    
    $jwt = new Jwt($providedJwt, $findSecret);
    $jwt->isValid();
    
If the secret is a callable the function will only be called once. Once it is called the secret will be replaced by the
functions return value.

####getSecret(): StringOption

Returns the secret as a string Some, or a None if there is no secret. If the secret is a callback function the callback
will be called.

    use maarky\Jwt\Jwt;
    
    $jwt = new Jwt();
    $jwt->getSecret(); //returns None
    $jwt->setSecret('secret');
    $jwt->getSecret(); //returns Some('secret')
    
    $jwt = new Jwt();
    $jwt->setSecret(function($jwt) { return 'secret'; });
    $jwt->getSecret(); //returns Some('secret')

###Algorithm Methods

####getSupportedAlgos(): array

Returns all of the algorithms that can be used.

####getAlgo(): StringOption

Returns the algorithm as a string Some or a string None if no algorithm has been set.

####setAlgo(string $algo)

Sets the algorithm to be used for creating the JWT signature. It must be one of the values provided by
getSupportedAlgos(), otherwise a maarky\Jwt\Exception will be thrown.

    use maarky\Jwt\Jwt;
    
    $jwt = new Jwt();
    $jwt->getSupportedAlgos(); //returns ['HS256', 'HS384', 'HS512']
    $jwt->getAlgo(); //returns string None
    $jwt->setAlgo('HS999'); // throws maarky\Jwt\Exception
    $jwt->setAlgo('HS256');
    $jwt->getAlgo(); // returns string Some('HS256')

###Encoding JWT

In order to encode a JWT you must have provided the following:

* At least one claim.
* A hashing algorithm.
* A secret.


    $jwt = new \maarky\Jwt\Jwt();
    $jwt->setAlgo('HS256');
    $jwt->addClaim('a', 'A');
    $jwt->setSecret('secret');
    echo $jwt->encode();
    //echoes eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI

###Validating A JWT

When validating a JWT the same requirements as encoding a JWT are in place. In addition, you must also provide a JWT to
validate against. If you created a Jwt object by providing a JWT as a string to the constructor you can call the
isValid() method without providing a JWT. However, if the Jwt object was not created in this way then you must provide a
JWT to the isValid() method.

    $validJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI';
    $invalidJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.XXX';
    $jwt = new \maarky\Jwt\Jwt($validJwt, 'secret');
    $jwt->isValid(); //returns true
    
    $jwt = new \maarky\Jwt\Jwt();
    $jwt->setAlgo('HS256');
    $jwt->addClaim('a', 'A');
    $jwt->setSecret('secret');
    $jwt->isValid($validJwt); //returns true
    $jwt->isValid($invalidJwt); //returns false

When validating a JWT it performs the following checks:

1. Makes sure a JWT was provided to validate against.
1. Make sure there are at least two headers and that the header contains a valid algorithm and type.
1. If an expiration (exp) claim is provided, makes sure that date is in the future.
1. If a not before (nbf) claim is provided, make sure that date is now or in the past.
1. If a issues at (iat) claim is set, make sure that date is in the past.
1. If an issued at (iat) and a not before (nbf) claim is set, make sure that issued at is older than not before.
1. Runs any custom validators that were provided, if any.
1. Encode the Jwt object and make sure it is equal to the JWT that you are comparing against.

####Custom Validators

You can add custom validators if necessary. This can be useful if you want to make sure the JWT isn't too old (by 
checking the issued at claim) or that the JWT has never been used before by checking that the public JWT ID claim (jti)
is unique. The validators must accept the Jwt object as its only argument and return a boolean.

#####addValidator(callable $validator)

Add a single validator. For example, make sure the JWT was issued no more than five minutes ago.

    $jwt->addValidator(function(Jwt $jwt) {
        return $jwt->getClaim('iat')
                   ->orElse(new Some(0))
                   ->filter(function($value) { return $value + (60 * 5) > time(); })
                   ->isDefined();
    });

#####addValidators(array $validators)

Add multiple validators. Each validator provided must be a callable.

#####getValidators(): ArrayOption

Return an array Option containing validators. An array None will be returned if no validators have been set, otherwise
an array Some will be returned.

