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

The header must contain a type (typ) and the hashing algorithm (algo) used to create the signature. You are allowed to
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

This library provides two Jwt classes, one mutable and the other immutable. The idea is that when you receive a JWT you
will validate it using the immutable Jwt class because you do not want to change it before testing its validity. However,
when creating a JWT you may need to change it beyond what you set in the constructor.

Both the mutable and immutable classes implement the same Jwt interface which means that they both have methods allowing
you to add and remove headers and claims. The difference between how these methods are implemented is that the mutable
class allows you to change the object directly whereas the immutable class creates a mutable version of itself, applies
the change to that mutable version and returns it. So no change is ever made to the immutable Jwt class. 

Both the mutable and immutable classes provide methods to retrieve a mutable and immutable version of themselves. If you
call the getMutable() method on the mutable class or the getImmutable() method on the immutable class they will simply
return themselves. If you call them on the opposite classes they will create a new mutable or immutable version of
themselves and return that. When creating an immutable JWT from a mutable JWT using the getImmutable() method the
immutable Jwt object will be marked as untrusted. This is to let you know that the Jwt is not guaranteed to match a JWT
provided by the client so its validation cannot be trusted. Also, all mutable Jwt objects are set as untrusted.

    use maarky\Jwt\Immutable\Jwt as ImmutableJwt;
    use maarky\Jwt\Mutable\Jwt as MutableJwt;
    
    $immutableJwt = new ImmutableJwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $immutableJwt->isTrusted(); //true
    
    $mutableJwt = $immutableJwt->getMutable();
    $mutableJwt->isTrusted(); //false
    $immutableJwt_2 = $mutableJwt->getImmutable();
    $immutableJwt_2->isTrusted(); //false
    
    $mutableJwt_2 = new MutableJwt();
    $mutableJwt_2->isTrusted(); //false

No methods exist to change whether or not a Jwt object is trusted.

If you're wondering what's the point in making changes to an immutable Jwt consider a scenario where you provide a JWT
to the client. When they make a request using that JWT you might issue them a new JWT with an updated expiration.

    $immutableJwt = new ImmutableJwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    if($immutableJwt->isValid()) {
        $response->setJwt($immutableJwt->addHeader('exp', time() + (60 * 10)->encode());
    }
    

Also, when creating a mutable object it will set the typ header to "JWT" and the alg header to "HS256" if no values were
provided. These values can be changed later using the addHeader(), addHeaders(), setType() and setAlgo() methods.

Creating a Jwt Object
---------------------

Here's how you would validate a JWT:

    use maarky\Jwt\Immutable\Jwt;
    
    $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns true
    
    $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw');
    $jwt->setSecret('secret');
    $jwt->isValid(); //returns true
    
    $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'bad secret');
    $jwt->isValid(); //returns false because the secret is bad
    
    $jwt = new Jwt('XXXeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns false because the header has changed
    
    $jwt = new Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XXXeyJzdWIiOjEyMzQ1Nn0.iJGpiQ7KAWGnbAkmKchWn99ZGjQX7kY0PwgwP_u9Jbw', 'secret');
    $jwt->isValid(); //returns false because the claims have changed

Here's how you would create a new JWT:

    use maarky\Jwt\Mutable\Jwt;
    
    $header = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    $claims = [
        'sub' => 123456
    ];
    $secret = 'secret';
    
    $jwt = new Jwt($claims, $secret, $header);
    
    //or 
    
    $jwt = new Jwt($claims, $secret); //no header provided so the defaults are used
    $jwt->isValid(); //returns true
    $jwt->encode(); //returns the encoded JWT

You can also create an empty mutable Jwt object:

    $jwt = new \maarky\Jwt\Mutable\Jwt();
    $jwt->addHeaders($header)
        ->addClaims($claims)
        ->setSecret($secret)
        ->encode();

Jwt Methods
-----------

The Jwt class has methods for adding and retrieving claims, headers and the secret and for encoding and validating the
Jwt object.

###Header Methods

####addHeader(string $header, $value): Jwt

Provide the header key and a value.

Calling this method on a mutable Jwt updates the object directly.  
Calling this method on an immutable Jwt creates a mutable Jwt with the new headers.

    $jwt->addHeader('header_key', 'header value');

####addHeaders(array $headers): Jwt

Use this method if you have an array of headers that you want to provide all at once.

Calling this method on a mutable Jwt updates the object directly.  
Calling this method on an immutable Jwt creates a mutable Jwt with the new headers.

    $headers = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];
    
    $jwt->addHeaders($headers);

####getHeader(string $header): Option

Retrieve a specific header. Returns a Some if the header is found, otherwise a None.  

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

Retrieve all headers as an array Option.

    $jwt = new Mutable\Jwt($headers);
    $jwt->getHeaders(); //returns Some(['typ' => 'JWT', 'alt' => 'HS256'])
    
####removeHeader(string $header): Jwt

If you want to remove a header call this method and provide the key for the header you want to remove.

Calling this method on a mutable Jwt updates the object directly.  
Calling this method on an immutable Jwt creates a mutable Jwt with the new headers.

    $jwt = new Mutable\Jwt();
    $jwt->removeHeader('alg');
    $jwt->getHeaders(); //returns Some(['typ' => 'JWT'])

###Claims Methods

####addClaim(string $claim, $value): Jwt
####addClaims(array $claim): Jwt  
####getClaim(string $claim): Option  
####getClaims(): ArrayOption  
####removeClaim(string $claim): Jwt

These methods work exactly like the respective header methods.

Calling the add and remove methods on a mutable Jwt updates the object directly.  
Calling the add and remove methods on an immutable Jwt creates a mutable Jwt with the new claims.

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

####setSecret($secret): Jwt

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
the functions return value.

####getSecret(): StringOption

Returns the secret as a string Some, or a None if there is no secret. If the secret is a callback function the callback
will be called.

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

####setAlgo(string $algo): Jwt

Sets the algorithm to be used for creating the JWT signature. It must be one of the values provided by
getSupportedAlgos(), otherwise a maarky\Jwt\Exception will be thrown.

    $jwt = new Jwt();
    $jwt->getSupportedAlgos(); //returns ['HS256', 'HS384', 'HS512']
    $jwt->getHeader('alg'); //returns string None
    $jwt->setAlgo('HS999'); // throws maarky\Jwt\Exception
    $jwt->setAlgo('HS256');
    $jwt->getHeader('alg'); // returns string Some('HS256')

###Encoding JWT

In order to encode a JWT you must have provided the following:

* At least one claim.
* A hashing algorithm (default "HS256" on mutable Jwt).
* A type (default "JWT" on mutable Jwt).
* A secret.

For example:

    $jwt = new Mutable\Jwt();
    $jwt->addClaim('a', 'A');
    $jwt->setSecret('secret');
    echo $jwt->encode();
    //echoes eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI
    
    $jwt = new Immutable\Jwt('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI', 'secret');
    echo $jwt->encode();
    //echoes eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI

###Validating A JWT

When validating a JWT the same requirements as encoding a JWT are in place. However, mutable and immutable Jwt objects
are not validated the same. A mutable Jwt performs the following tests: 

1. Make sure a secret has been set
1. Make sure there are at least two headers and that the header contains a valid algorithm and type.
1. If an expiration (exp) claim is provided, makes sure that date is in the future.
1. If a not before (nbf) claim is provided, make sure that date is now or in the past.
1. If a issued at (iat) claim is set, make sure that date is in the past.
1. If an issued at (iat) and a not before (nbf) claim is set, make sure that issued at is older than not before.
1. Runs any custom validators that were provided, if any.

An immutable Jwt performs the same tests against the data provided in the base64 encoded header and claimset. If those
tests pass it will then create a signature using the base64 encoded header and claimset and the secret. It validates if
this signature matches what was provided to the constructor.

    $validJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.4qVGOwVxKEQJP576JoiEJg1cgvB86r6CCZI_RsYAUlI';
    $invalidJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiQSJ9.XXX';
    $jwt = new \maarky\Jwt\Immutable\Jwt($validJwt, 'secret');
    $jwt->isValid(); //returns true
    
    $jwt = new \maarky\Jwt\Immutable\Jwt($invalidJwt, 'secret');
    $jwt->isValid(); //returns false
    
    $jwt = new \maarky\Jwt\Mutable\Jwt();
    $jwt->addClaim('a', 'A');
    $jwt->setSecret('secret');
    $jwt->isValid(); //returns true

The general idea is that validating an immutable Jwt tells you that the request is authentic. Validating a mutable Jwt
tells you whether or not it is ready to be encoded. After all, there's no point in encoding and using a Jwt that will
not be accepted by the recipient.

####Custom Validators

You can add custom validators if necessary. This can be useful if you want to make sure the JWT isn't too old (by 
checking the issued at claim) or that the JWT has never been used before by checking that the public JWT ID claim (jti)
is unique. The validators must accept the Jwt object as its only argument and return a boolean.

#####addValidator(callable ...$validators): Jwt

Add one or more validators. For example, make sure the JWT was issued no more than five minutes ago.

    $jwt->addValidator(function(Jwt $jwt) {
        return $jwt->getClaim('iat')
                   ->filter(function($value) { return $value + (60 * 5) > time(); })
                   ->isDefined();
    });
    
    // add many validators by providing as many arguments as you need
    $jwt->addValidator($function1, $function2, $junction3);
    //or unpack an array of validators
    $jwt->addValidator(...[$function1, $function2]);

#####getValidators(): ArrayOption

Return an array Option containing validators. An array None will be returned if no validators have been set, otherwise
an array Some will be returned.

