PyEC
====

A set of modules and a simple chat in Python to illustrate key exchange, cryptography and discrete logarithm problems applied to rational points of elliptic curves over a finite field.

All the modules are well documented, here there is just a quick example of the main functionalities.

The `ec` module
---------------
The `ec` module provides support to define and manipulate rational points on elliptic curves. Two classes are defined in it, `EC` and `ECPt`, representing respectively an elliptic curve over a finite field (of equation *y^2=x^3+ax^2+bx+c*) and a point on it.

#### Definition of an elliptic curve

Just call the constructor `EC(a,b,c,p)`, providing the three coefficient of the equation and *p*, a prime number that defines the finite field:
<pre>
  >>> from modules.ec import *
	>>> curve = EC(0, 5, 2, 967)
	>>> str(curve)
	'y^2==x^3+5x+2 over F_967'
</pre>

#### Point manipulation

We can generate a point on the curve by calling the constructor `ECPt(curve,x,y)`, or using the method `pickPoint()` of the curve we just defined.
<pre>
	>>> P = ECPt(curve, 8, 39)
	>>> Q = curve.pickPoint()
	>>> str(P), str(Q)
	('[8, 39]', '[40, 185]')
</pre>
The operation of addition between points (as well as the multiplication by a scalar value) is implemented into the two builtin operators `+` and `*`. Let's compute *P+Q*, *P+P* and the first multiples of *P*:
<pre>
	>>> str( P+Q )
	'[309, 703]'
	>>> str( P+P )
	'[756, 105]'
	>>> for i in range(2, 5):       # i = 2, 3, 4
	...     str( i*P )
	...
	'[756, 105]'
	'[157, 602]'
	'[783, 349]'
	>>> ( 2*P ) == ( P+P )
	True
	>>> str( 345*P )
	'[697, 843]'
</pre>
The neutral element *O* can be obtained calling the static method `ECPt.identity()`. To verify if a given point is the identity, you can check the return value of `isIdentity()`, a method of `ECPt`. Let's see an example where we perform basic checks on the identity:
<pre>
	>>> O = ECPt.identity()
	>>> P+O == O+P == P
	True
	>>> O == 2*O == O+O == -O == 50*O
	True
	>>> str( P-P )
	'O'
	>>> R = 41*P
	>>> S = -41*P
	>>> ( R+S ).isIdentity()
	True
	>>> 0*P == O
	True
</pre>

#### Order of points and cardinality of the rational points group

The method that computes the cardinality of the rational points group is based on three auxiliary algorithms:
* `minOrderWithConstraints(...)` (instance method of `ECPt`);
* `orderInFactorGroup(...)` (static method `ECPt`);
* `cardinality()` (method of `EC`).

Let's try the third algorithm, as the result can be appreciated immediately:
<pre>
	>>> curve.cardinality()
	976
	>>> othercurve = EC(1, 2, 300, 25169)
	>>> othercurve.cardinality()
	25136
	>>> P = othercurve.pickPoint()
	>>> str(P), str( 25136*P )
	('[20982, 1348]', 'O')
</pre>
Another method is provided: `enumerateAllPoints()`; it returns a list of all the rational points (relying on `cardinality()` to stop the scanning loop).
<pre>
	>>> points = othercurve.enumerateAllPoints()
	>>> len(points)
	25136
</pre>

The `dlog` module
-----------------
This module implements Shanks's and Pohlig-Hellman's algorithms, optimizing the execution time using sorted lists.
The methods provided here are generic: they work perfectly on any object provided with the operations `+` and `-`, as well as scalar multiplication (`*` between an object and a int); because of that, they can be used in any group.

#### Shanks's method

This algorithm is implemented in two versions, `shanks(a,b,bs,gs)` and `autoshanks(a,b,n)`. The first allows the user to specify the number of baby and giant steps, the seconds instead requires the knowledge of the cardinality *n* of the group used, and sets the number of steps both to *sqrt(n)*.
<pre>
	>>> from modules.dlog import autoshanks, pohlighellman
	>>> Q = 3343*P
	>>> autoshanks(P, Q, 25136)
	3343L
</pre>

#### Pohlig-Hellman's method

The method `pohlighellman(a, b, n)` computes the discrete logarithm using the factorization of *n*. 25136 is small enough for the factorization to be computed quickly:
<pre>
	>>> pohlighellman(P, Q, 25136)
	3343L
</pre>
Also the method `computeOrder()` of the class `ECPt` relies on Shanks's algorithm. `computeOrder()` returns the order of a point in the rational points group. The method `pickGenerator()` of `EC` takes advantage of both this method and `cardinality()` to find a point with order equal to *#C_k*:
<pre>
	>>> P, Q = curve.pickPoint(), othercurve.pickPoint()
	>>> P.computeOrder(), Q.computeOrder()
	(122L, 12568L)
	>>> G = othercurve.pickGenerator()
	>>> G.computeOrder()  # we expect 25136
	25136L
</pre>

Cryptographic modules
---------------------
The `cryptohelp` and `ecdh` modules provide methods, such as `ecdh_init(...)` and `ecdh_reply(...)`, that allow to implement Diffie-Hellman protocol on elliptic curves. More specifically, the class `ECDHSession` manages key exchange.
Let's see an example of these methods altogether.

The script can be launched by running `python main.py`; it opens a connection between two machines via TCP/IP, then proceeds with a key exchange as in Diffie-Hellman protocol.

With rational points as group, the choice of the parameters implies the choice of a particular finite field and an elliptic curve on it. The machine that begins key exchange (let's call it *M*) performs the following operations:
1. Chooses a random prime *p*.
2. Randomly chooses paramteres to define an elliptic curve.
3. Chooses a random integer *A* and a generator *g* of the rational points group.

Then it sends to the other machine, *D*, the parameters *a*, *b*, *c*, the number *p*, the points *g* and *Ag*, and waits for a reply.

The machine *D* receives the parameters and chooses a random integer *B*; then sends *Bg* to *M*.

*M* receives *Bg* and computes *ABg*. From this last point, it derives a key and uses it to initialize a symmetric cypher (Salsa20 in this case).
Now  *M* sends a first encrypted message *m_1*.

*D* receives *m_1* encrypted; it computes only now *ABg* with the known data, derives from *ABg* the same key that *M* has, initializing its own symmetric cypher.
It uses then the cypher to decrypt and check *m_1*. It it matches the expected value, it prepares another confirmation message *m_2*, encrypts it and sends it to *M*.
At this point *D* has finished its role in the key exchange.

*M* receives *m_2*, decrypts it and checks its correctness; the key exchange is concluded.

The software allows now the users to type and exchange messages: the inserted text is encrypted using the key derived from *ABg*.

Follows a sample run of `main.py`.

### The machine *M*
<pre>
>>> connect or listen? connect
>>> ip address (empty=>localhost)? 
... net: starting listening thread
... net: connecting to localhost:55755
... net: listening thread started
... crypto: generating a random pseudoprime
... crypto: chosen 48239
... crypto: picking random a, b, c to define an e.c.
... crypto: y^2==x^3+26531x^2+36476x+38073 over F_48239
... crypto: looking for a generator of the rational pts group
... crypto: using [20999, 24164] as generator
... crypto: choosing a random integer a
... crypto: chosen 11798761, a*g is [591, 44543]
... crypto: using bg=[44972, 26192]
... crypto: computed ab*g=[33338, 6910]
... crypto: deriving key from [33338, 6910]
... crypto: the key computed is e2fc1d9ef1630eac4e7b2fbc76a969b058b1917e29304181
...                             7103c0c980ab7d534a59cd5731c20e0ccefaeaedc80a8d5f
... ecdh: key exchange done. Parameters:
...           curve - y^2==x^3+26531x^2+36476x+38073 over F_48239
...     generator g - [20999, 24164]
...        secret a - 11798761
...             a*g - [591, 44543]
...             b*g - [44972, 26192]
...     secret ab*g - [33338, 6910]
...             key - e2fc1d9ef1630eac4e7b2fbc76a969b058b1917e29304181
...                   7103c0c980ab7d534a59cd5731c20e0ccefaeaedc80a8d5f
... ecdh: sending the hash of ec as reply
... ecdh: encrypting '.\xd9nK\x80\x18\xa3\x0c?\xc0\xfb(\xaa\x9dA\xfa'
... ecdh: sending '\xe6\x03\x07\xbf\x9e:Z\x9a\xceI\xee\x87rzxz&\xd7\xb1H'...
... ecdh: checking message against a*g, b*g hash
... ecdh: decrypting '`\xd3?\xd1+\\D{\xf0\x1c8\xb3\xf4&Gs\xea\x9d\x8a\xf5'...
... ecdh: encrypted session ready
... ecdh: received encrypted message
... ecdh: decrypting ' \x8e\x87\xfe.\xa2/x\x8b\xea\x87rw$\xc1\xaa6\xa9\x91\xb1'...
<<< FERMAT
EULERO
... ecdh: encrypting 'EULERO'
... ecdh: sending 't\xd9\xd7\x82?pL\xb3\xc6[Q\x18\xdb\x01q<\xf0\xeb8\xbe'...
... ecdh: received encrypted message
... ecdh: decrypting '\x0e\xcf\xfa0\xfd\xe1slZ)5/\xb0;\x01^\x88z8\x00'...
<<< Curve ellittiche
Moduli in Python
... ecdh: encrypting 'Moduli in Python'
... ecdh: sending '*\xe9\x8eY\x06\xb0)\xec\x96\xc7\xafA\x0eIl\xf2Sa\xce\xb6'...
</pre>
### The machine *D*
<pre>
>>> connect or listen? listen
>>> choose one of the network interfaces to bind (empty=>loopback lo0):
	en1	140.105.232.19
	lo0	127.0.0.1
>>> 
... ready to listen at lo0 on 127.0.0.1
... wait for an incoming connection before typing!
... net: incoming connection from ('127.0.0.1', 59456)
... crypto: using the e.c. y^2==x^3+26531x^2+36476x+38073 over F_48239
... crypto: using the generator [20999, 24164]
... crypto: a*g=[591, 44543]
... crypto: choosing a random b
... crypto: chosen 14429519, b*g is [44972, 26192]
... crypto: computed ab*g, that is [33338, 6910]
... crypto: deriving key from [33338, 6910]
... crypto: the key computed is e2fc1d9ef1630eac4e7b2fbc76a969b058b1917e29304181
...                             7103c0c980ab7d534a59cd5731c20e0ccefaeaedc80a8d5f
... ecdh: key exchange done. Parameters:
...           curve - y^2==x^3+26531x^2+36476x+38073 over F_48239
...     generator g - [20999, 24164]
...        secret b - 14429519
...             a*g - [591, 44543]
...             b*g - [44972, 26192]
...     secret ab*g - [33338, 6910]
...             key - e2fc1d9ef1630eac4e7b2fbc76a969b058b1917e29304181
...                   7103c0c980ab7d534a59cd5731c20e0ccefaeaedc80a8d5f
... ecdh: decrypting '\xe6\x03\x07\xbf\x9e:Z\x9a\xceI\xee\x87rzxz&\xd7\xb1H'...
... ecdh: replying with the hash of a*g, b*g
... ecdh: encrypting '\xf0y\xc5G\r{\xc5 \xf1\xb2s\xac\xdel\x031'
... ecdh: sending '`\xd3?\xd1+\\D{\xf0\x1c8\xb3\xf4&Gs\xea\x9d\x8a\xf5'...
... ecdh: encrypted session ready
FERMAT
... ecdh: encrypting 'FERMAT'
... ecdh: sending ' \x8e\x87\xfe.\xa2/x\x8b\xea\x87rw$\xc1\xaa6\xa9\x91\xb1'...
... ecdh: received encrypted message
... ecdh: decrypting 't\xd9\xd7\x82?pL\xb3\xc6[Q\x18\xdb\x01q<\xf0\xeb8\xbe'...
<<< EULERO
Curve ellittiche
... ecdh: encrypting 'Curve ellittiche'
... ecdh: sending '\x0e\xcf\xfa0\xfd\xe1slZ)5/\xb0;\x01^\x88z8\x00'...
... ecdh: received encrypted message
... ecdh: decrypting '*\xe9\x8eY\x06\xb0)\xec\x96\xc7\xafA\x0eIl\xf2Sa\xce\xb6'...
<<< Moduli in Python
</pre>
