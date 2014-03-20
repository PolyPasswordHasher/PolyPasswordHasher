PolyPassHash
============

A Password hashing scheme that prevents an attacker from cracking passwords individually.   


Summary
=======

Typically a password server securely obtains a password from the user, performs a salted hash on the password, and then checks if that entry matches what is in the password database under that user name.   Hackers have proven adept at stealing password databases from [dozens](https://isis.poly.edu/~jcappos/papers/tr-cse-2013-02.pdf) [of](http://www.zdnet.com/blog/security/pwnedlist-alerts-you-when-youve-been-hacked-for-a-price/10943) [companies](http://blog.passwordresearch.com/2013/02/ passwords-found-in-wild-for-january-2013.html).  An attacker with the password database can try different passwords for a user and check if there is a match.

PolyPassHash stores password data in a different way ([technical details](https://github.com/JustinCappos/PolyPassHash/blob/master/academic-writeup/paper.pdf)).   To understand the concept, imagine a flat piece of paper.   Instead of storing the salted password hash, PolyPassHash combines this value with a point on the piece of paper.   All of the correct passwords when salted will produce points that lie on the same line.   (The information about this line is a secret that is not stored on disk.)   When an attacker tries to crack passwords, they will simultaneously guess multiple passwords, which makes it [amazingly hard to crack passwords](#hardtocompute).

When the server restarts, it also needs to recompute the line.   However, through the normal login process, users provide many correct passwords and so the server finds the line without problems.   This technique is very efficient for the server to compute and requires very little additional storage or memory.   Better yet, client computers do not need to be changed in any way to use this.   So hopefully this technique will be coming to your favorite service to protect your password!


FAQ
===

<a name="hardtocompute"/>
#### "How hard is it to crack passwords stored using this technique?"

Suppose that you have three people who have random passwords that are randomly chosen and 6 characters long.   A typical laptop can crack those passwords in about 1 hour.   

If you take the same passwords and protect them with PolyPassHash, every computer on the planet working together cannot crack the password in 1 hour.   In fact, it would every computer on the planet [longer than the universe is estimated to have existed](https://github.com/JustinCappos/PolyPassHash/blob/master/academic-writeup/paper.pdf).

<a name="thresholdless"/>
#### "What about a service like Facebook or Gmail where anyone can register an account?"

It is possible to use accounts that contribute to the line (threshold accounts) as a key to encrypt other account credentials (thresholdless account).   So an attacker can know any number of those thresholdless accounts and cannot crack other thresholdless account or the threshold accounts.   


<a name="breakssystem"/>
#### "What if an attacker figures out the sensitive information (line)?"

The account passwords are still salted and hashed.   So accounts are still protected using the standard salted and hashed techniques that people leverage today.   So in the worst case, PolyPassHash provides the same protection as what people are using today.

<a name="restart"/>
#### "If the attacker can't check individual accounts, how does the server check the first account after rebooting?"

The basic technique described here would require some number of users to provide correct login information before authorizing any of them.   However, [our paper](https://github.com/JustinCappos/PolyPassHash/blob/master/academic-writeup/paper.pdf) discusses an extension that gets around this issue.   You can leak a small amount of information about the password hashes to allow checking.   Using the example above, this is similar to leaking the last few digits of the points.   An attacker still has a huge number of things to guess, but the server can check and eliminate most wrong passwords right after reboot.

<a name="weakpasswords"/>
#### "Does this mean I can choose very weak passwords on sites that use PolyPassHash?"

Extremely weak passwords are a bad idea.   An attacker can guess things like password, etc. and just try them even if they do not have the database.   So do not use them regardless of the storage technology.

Another thing PolyPassHash does not protect against is password reuse.   Do not use the same password on multiple sites no matter how strong it is!   We recommend using a [password](https://lastpass.com) [manager](https://agilebits.com/onepassword) that generates a separate, strong password per site.

<a name="hashalg"/>
#### "What secure hash algorithm does PolyPassHash use?"

Any secure hashing algorithm can be used with PolyPassHash.   The [Python reference implementation](python-reference-implementation) uses SHA256.


<a name="implementation"/>
#### "Where can I get an implementation of PolyPassHash?"

This repository, contains the [PolyPassHash Python reference implementation](python-reference-implementation).   This is written for readability and not performance or practical use.   There is also a [C implementation](https://github.com/SantiagoTorres/PolyPassHash-C) underway.

Please contact us if you have an implementation of PolyPassHash that you would like us to list.


<a name="moreinfo"/>
#### "How do I get more information about PolyPassHash?"

[Our paper](https://github.com/JustinCappos/PolyPassHash/blob/master/academic-writeup/paper.pdf) should be a good starting point.   If you have a question that is not covered there, feel free to email me (jcappos@nyu.edu) and ask.
