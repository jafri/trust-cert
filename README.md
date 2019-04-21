# trust-cert [![Build Status](https://travis-ci.com/jafri/trust-cert.svg?branch=master)](https://travis-ci.com/jafri/trust-cert)

> Trust Root Certificates in MacOs, Linux, Windows and Firefox (nss)

[Docs](https://jafri.github.io/trust-cert)

## Installation
NPM
```
npm i trust-cert
```

Yarn
```
yarn add trust-cert
```

## Install Certificate
```js
import { generateTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = generateTrust()

(async () => {
    await trust.installFromFile(certPath, 'EOS Root CA')
})
```

## Uninstall Certificate
```js
import { generateTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = generateTrust()

(async () => {
    await trust.uninstall(certPath, 'EOS Root CA')
})
```

## NSS (Firefox) Certificate Install
Firefox does not use system store, so we package cross-platform nss binaries.

```js
import { NssTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new NssTrust()

(async () => {
    await trust.installFromFile(certPath, 'EOS Root CA')
})
```

## NSS (Firefox) Certificate Uninstall
Firefox does not use system store, so we package cross-platform nss binaries.

```js
import { NssTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new NssTrust()

(async () => {
    await trust.uninstall(certPath, 'EOS Root CA')
})
```

Note: The tests install the root CA in the certs folder into your store, modify the certs folder if you wish to test with your own cert.

Credits: [mkcert](https://github.com/FiloSottile/mkcert)