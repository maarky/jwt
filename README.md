PHP JWT
=======

A JSON Web Token, or JWT (pronounced "jot"), is a means of authentication. It allows a requester to create their own
authentication token that can be validated by the recipient. For details go [here](https://jwt.io/introduction/).

This implementation only supports HMAC secrets. It does not support RSA public and private keys.

About JWTs
----------

In short, a JWT consists of three parts: a header, a claimset and a signature. The header and claimset are base64
encoded JSON objects and the signature is a base64 encoded hash of the header and claimset. These parts are concatenated
together separated by a period.

The header must contain a type (typ) and the hashing algorithm (alg) used to create the signature. You are allowed to
provide additional headers but these are the only two that are required.

Consider the following JWT:

    Header: {"alg":"HS256","typ":"JWT"}
    Claims: {"a":"claim A","b":"claim B","c":"claim C"}
    
    Base64 encoding the header and claims produces the following:
    
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMifQ
    ^----------------------------------^ ^--------------------------------------------------------^
     Header                               Claims
     
     Hashing the above with the HS256 hashing algorithm using the key "secret" provides the following base64 encoded
     signature:
     
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

PHP 7
-----

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

This library provides two Jwt classes, a Generator and a Validator. The idea is that when you receive a JWT you
will validate it using the immutable Validate class. However, when creating a JWT you use the mutable Generator class. 
Both classes implement the same Jwt interface so they both have methods allowing you to access headers, claims and 
the secret as well as testing validity.

The Generator class has defaults for the typ and alg headers so these defaults will be used if no header is provided or if 
a header is provided without a typ or alg.

    $jwt = new Generator();
    
    or
    
    $jwt = new Generator([], '', ['var' => 'val']);
    
    $jwt->getHeader('typ'); //returns Some('JWT')
    $jwt->getHeader('alg'); //returns Some('HS256')
    
A Validator does not have any defaults so anything not passed into the constructor will not be there.  

Creating a Jwt Object
---------------------

Here's how you would validate a JWT:

    use maarky\Jwt\Validator;
    
    $jwt = new Validator('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns true
    
    $jwt = new Validator('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw');
    $jwt->setSecret('secret');
    $jwt->isValid(); //returns true
    
    $jwt = new Validator('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'bad secret');
    $jwt->isValid(); //returns false because the secret is bad
    
    $jwt = new Validator('XXXeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns false because the header has changed
    
    $jwt = new Validator('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XXXeyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns false because the claims have changed

Here's how you would create a new JWT:

    use maarky\Jwt\Generator;
    
    $header = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    $claims = [
        'sub' => 123456
    ];
    $secret = 'secret';
    
    $jwt = new Generator($claims, $secret, $header);
    
    or 
    
    $jwt = new Generator($claims, $secret); //no header provided so the defaults are used
    $jwt->isValid(); //returns true
    $jwt->encode(); //returns the encoded JWT

You can also create an empty Generator object:

    $jwt = new \maarky\Jwt\Generator();
    $jwt->addHeaders($header)
        ->addClaims($claims)
        ->setSecret($secret)
        ->encode();

Jwt Methods
-----------

The Jwt interface supports the following methods.

### Header Methods

#### getHeader(string $key): Option

Retrieve a specific header. Returns a Some if the header is found, otherwise a None.  
    
    $jwt = new Generator();
    
    $jwt->addHeader('typ', 'JWT');
    $jwt->getHeader('typ'); //returns Some('JWT')
    $jwt->getHeader('typo'); //returns None
    
    //determining if a header exists
    $jwt->getHeader('typ')->isDefined(); // returns true
    $jwt->getHeader('typ')->isEmpty(); // returns false
    $jwt->getHeader('typo')->isDefined(); // returns false
    $jwt->getHeader('typo')->isEmpty(); // returns true

#### getHeaders(): array

Retrieve all headers as an array.

    $headers = ['typ' => 'JWT', 'alt' => 'HS256'];
    $jwt = new Generator([], '', $headers);
    $jwt->getHeaders(); //returns ['typ' => 'JWT', 'alt' => 'HS256']
    
### Claims Methods

#### getClaim(string $key): Option  
#### getClaims(): array  

These methods work exactly like the respective header methods.

### Secret Methods

#### setSecret($secret): Jwt

When setting a secret you can provide a string or a callback function. If a callback is provided it will be passed the
Jwt object and must return a string. If the secret is a callback it will be called when calling the getSecret() method.
This method is only called internally when encoding the Jwt object and when validating the object so a secret must be
provided before either of those occur.

Providing a callback can be useful if you need something from the claims in order to retrieve the secret. For example:

    $providedJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiY2xhaW0gQSIsImIiOiJjbGFpbSBCIiwiYyI6ImNsYWltIEMiLCJwdWJrIjoiams0NTM0a2pia2o0NSJ9.EZqOXe1dizNCK3zlSTDV54KflwJx2MZg6qdvSLr7Q_0';
    $findSecret = function(Jwt $jwt) use($repository) {
        return $jwt->getClaim('pubk')
                   ->flatMap(function($value) { return $repository->findSecret($value); })
                   ->getOrElse('');
    };
    
    $jwt = new Jwt($providedJwt, $findSecret);
    $jwt->isValid();
    
If the secret is a callable the function will only be called once. Once it is called the callback will be replaced by
the function's return value.

#### getSecret(): StringOption

Returns the secret as a string Some, or a None if there is no secret. If the secret is a callback function the callback
will be called.

    $jwt = new Jwt();
    $jwt->getSecret(); //returns None
    $jwt->setSecret('secret');
    $jwt->getSecret(); //returns Some('secret')
    
    $jwt = new Jwt();
    $jwt->setSecret(function($jwt) { return 'secret'; });
    $jwt->getSecret(); //returns Some('secret')

### Algorithm Methods

#### getSupportedAlgs(): array

Returns all of the algorithms that can be used.

#### setAlg(string $alg): Jwt

Sets the algorithm to be used for creating the JWT signature. It must be one of the values provided by
getSupportedAlgos(), otherwise a maarky\Jwt\Exception will be thrown.

    $jwt = new Jwt();
    $jwt->getSupportedAlgos(); //returns ['HS256', 'HS384', 'HS512']
    $jwt->getHeader('alg'); //returns string None
    $jwt->setAlgo('HS999'); // throws maarky\Jwt\Exception
    $jwt->setAlgo('HS256');
    $jwt->getHeader('alg'); // returns string Some('HS256')
    
This method is only available in a Generator.

### Encoding JWT

In order to encode a JWT you must have provided the following:

* At least one claim.
* A hashing algorithm (default "HS256" on Generator).
* A type (default "JWT" on Generator).
* A secret.

For example:

    $jwt = new Generator();
    $jwt->addClaim('a', 'A');
    $jwt->setSecret('secret');
    echo $jwt->encode();
    //echoes eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI
    
    $jwt = new Validator('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI', 'secret');
    echo $jwt->encode();
    //echoes eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI

### Validating A JWT

When validating a JWT the same requirements as encoding a JWT are in place. However, Generator and Validator Jwt objects
are not validated the same. All Jwt performs the following tests, using the following keys: 

1. "secret": Make sure a secret has been set
1. "alg": Make sure there is a valid alg header.
1. "typ": Make sure there is a valid typ header.
1. "exp": If an expiration (exp) claim is provided, makes sure that date is in the future.
1. "nbf": If a not before (nbf) claim is provided, make sure that date is now or in the past.
1. "iat": If a issued at (iat) claim is set, make sure that date is in the past.

A Validator Jwt performs the same tests against the data provided in the base64 encoded header and claimset. If those
tests pass it will then create a signature using the base64 encoded header and claimset and the secret. It validates if
this signature matches what was provided to the constructor.

The general idea is that validating a Validator Jwt tells you that the request is authentic. Validating a Generator Jwt
tells you whether or not it is ready to be encoded. After all, there's no point in encoding and using a Jwt that will
not be accepted by the recipient.

#### Custom Validators

You can add custom validators if necessary. This can be useful if you want to make sure the JWT isn't too old (by 
checking the issued at claim) or that the JWT has never been used before by checking that the public JWT ID claim (jti)
is unique. The validators must accept the Jwt object as its only argument and return a boolean.

##### addValidator(string $name, callable $validator): Jwt

Add one validator, using the given key. For example, make sure the JWT was issued no more than five minutes ago.

    $jwt->addValidator('iat', function(Jwt $jwt) {
        return $jwt->getClaim('iat')
            ->filter(function($value) { return $value + (60 * 5) > time(); })
            ->isDefined();
    });
    
    // add many validators by providing as many arguments as you need
    $jwt->addValidator($function1, $function2, $junction3);
    //or unpack an array of validators
    $jwt->addValidator(...[$function1, $function2]);
    
The Jwt already has a validator using the "iat" key so this validator will replace the default iat validator.

##### getValidators(): Array

Return an array containing validators. An empty array will be returned if no validators have been set.

##### removeValidator(string $name): Jwt

Removes the validator with the given key. Nothing happens if there is no validator with the given key.

##### clearValidators(): Jwt

Removes all validators.

##### getValidator(string $name): CallbackOption

Returns an Option containing the requested validator. If there is a validator with the given key you will get back
a Callback Some, otherwise you get a Callback None.

##### isTrusted(): bool

This method is basically meant to be a simple way to determine if you are dealing with a Generator or Validator Jwt. 
A Generator always returns FALSE while a Validator always returns TRUE. This allows you to know what it means if a Jwt 
is valid. A trusted Jwt can be used to validate a request while an untrusted Jwt cannot.