PolyPasswordHasher
============

A Password storage scheme that prevents an attacker from cracking passwords individually.   


Summary
=======

Password database disclousures have caused companies billions of dollars in
damages.   Typically a password server securely obtains a password from the
user, performs a salted hash on the password, and then checks if that entry
matches what is in the password database under that user name.   Hackers have
proven adept at stealing password databases from
[dozens](https://isis.poly.edu/~jcappos/papers/tr-cse-2013-02.pdf)
[of](http://www.zdnet.com/blog/security/pwnedlist-alerts-you-when-youve-been-hacked-for-a-price/10943)
[companies](http://blog.passwordresearch.com/2013/02/passwords-found-in-wild-for-january-2013.html).
An attacker with the password database can try different passwords for a user
and check if there is a match.

PolyPasswordHasher stores password data in a different way ([technical
details](https://github.com/PolyPasswordHasher/PolyPasswordHasher/blob/master/academic-writeup/paper.pdf)).
To understand the concept, imagine a flat piece of paper.   Instead of storing
the salted password hash, PolyPasswordHasher combines this value with a point
on the piece of paper.   All of the correct passwords when salted will produce
points that lie on the same line.   (For the cryptographically knowledgeable
reader, the actual construct used is a Shamir Secret Share instead of points in
a multi-dimensional space.)   The information about this line is a secret that
is not stored on disk.   When an attacker tries to crack passwords, they will
simultaneously guess multiple passwords (the line), which makes it [amazingly
hard to crack passwords](#hardtocompute).   

When the server restarts, it also needs to recompute the line.   However,
through the normal login process, users provide many correct passwords and so
the server finds the line without problems.   This technique is very efficient
for the server to compute and requires very little additional storage or
memory.   Better yet, client computers do not need to be changed in any way to
use this.   There are free, open source [implementations
available](#implementation) for PolyPasswordHasher. So hopefully this technique
will be coming to your favorite service to protect your password!


FAQ
===

<a name="hardtocompute"/>
#### "How hard is it to crack passwords stored using this technique?"

Suppose that three people have passwords that are each randomly chosen and 6
characters long.   A typical laptop can crack those passwords in about 1 hour.   

If you take the same passwords and protect them with PolyPasswordHasher, every
computer on the planet working together cannot crack the password in 1 hour.
In fact, to search the key space, it would take every computer on the planet
[longer than the universe is estimated to have
existed](https://github.com/PolyPasswordHasher/PolyPasswordHasher/blob/master/academic-writeup/paper.pdf).

<a name="thresholdless"/>
#### "What about a service like Facebook or Gmail where anyone can register an account?"

It is possible to use accounts that contribute to the line (threshold accounts)
as a key to encrypt other account credentials (thresholdless account).   So an
attacker can know any number of those thresholdless accounts and cannot crack
other thresholdless account or the threshold accounts.   


<a name="breakssystem"/>
#### "What if an attacker figures out the sensitive information (line / Shamir Secret Share)?"

This would require an attacker to be able to read memory from a running server.
Typically the server obtains the client's password in plain-text and then
performs the salted hash.   So if an attacker can read memory on a running
server, they can steal passwords unencrypted regardless of the technique that
is used.

However, even if an attacker can recover the line / Shamir Secret Share, the
account passwords are still salted and hashed.   So accounts are still
protected using the standard salted and hashed techniques that people leverage
today.   So in the worst case, PolyPasswordHasher provides the same protection
as what people are using today.

Furthermore, it turns out that the [most commonly disclosed cause of password
database compromise is SQL
injection](https://isis.poly.edu/~jcappos/papers/tr-cse-2013-02.pdf), which
does not imply the attacker can read arbitrary memory.   So in many cases, an
attacker that can steal the database does not have this access.

<a name="restart"/>
#### "If the attacker can't check individual accounts, how does the server check the first account after rebooting?"

The basic technique described here would require some number of users to
provide correct login information before authorizing any of them.   However,
[our
paper](https://github.com/PolyPasswordHasher/PolyPasswordHasher/blob/master/academic-writeup/paper.pdf)
discusses an extension that gets around this issue.   You can leak a small
amount of information about the password hashes to allow checking.   Using the
example above, this is similar to leaking the last few digits of the points.
An attacker still has a huge number of things to guess, but the server can
check and eliminate most wrong passwords right after reboot.

<a name="weakpasswords"/>
#### "Does this mean I can choose very weak passwords on sites that use PolyPasswordHasher?"

Extremely weak passwords are a bad idea.   An attacker can guess things like
password, etc. and just try them even if they do not have the database.   So do
not use them regardless of the storage technology.

Another thing PolyPasswordHasher does not protect against is password reuse.
Do not use the same password on multiple sites no matter how strong it is!   We
recommend using a [password](https://lastpass.com)
[manager](https://agilebits.com/onepassword) that generates a separate, strong
password per site.

<a name="hashalg"/>
#### "What secure hash algorithm does PolyPasswordHasher use?"

Any secure hashing algorithm can be used with PolyPasswordHasher.   The [Python
reference
implementation](https://github.com/PolyPasswordHasher/PolyPasswordHasher/tree/master/python-reference-implementation)
uses SHA256.


<a name="implementation"/>
#### "Where can I get an implementation of PolyPasswordHasher?"

This repository, contains the [PolyPasswordHasher Python reference
implementation](https://github.com/PolyPasswordHasher/PolyPasswordHasher/tree/master/python-reference-implementation).   This is written for
readability and not performance or practical use.   There is also a [C
implementation](https://github.com/PolyPasswordHasher/PolyPasswordHasher-C)
available.

We would love to see a PHP implementation for common frameworks because many
password hash breaches [occur on these
systems](http://blog.passwordresearch.com/2013/02/passwords-found-in-wild-for-january-2013.html).

Please contact us if you have an implementation of PolyPasswordHasher that you
would like us to list.


<a name="moreinfo"/>
#### "How do I get more information about PolyPasswordHasher?"

[Our
paper](https://github.com/PolyPasswordHasher/PolyPasswordHasher/blob/master/academic-writeup/paper.pdf)
should be a good starting point.   If you have a question that is not covered
there, feel free to email jcappos@nyu.edu.
