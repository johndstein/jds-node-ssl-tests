# Node SSL (HTTPS) Tests

Various examples of how to connect to node.js server over SSL.

Also examples of how to use SSL for client authentication.

I always pull my hair out getting all the SSL config stuff right, and then
the next time I have to do it I have forgotten, so . . . 

## Installation

    npm install

## Usage

    npm test

## Re-generate Certs

The following will delete all the current certs and re-generate them.
Play around with this is you want to see how to generate certs.

    cd certs
    ./gen-certs.sh

I used https://github.com/mikeal/request/tree/master/tests/ssl as a starting
point.
